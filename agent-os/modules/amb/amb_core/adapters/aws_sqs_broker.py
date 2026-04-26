# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AWS SQS broker adapter for AMB.

Amazon SQS provides fully managed message queues for microservices,
distributed systems, and serverless applications.
"""

import asyncio
import json
import uuid
from typing import Dict, List, Optional

from amb_core.broker import BrokerAdapter, MessageHandler
from amb_core.models import Message

try:
    import aioboto3
    from botocore.exceptions import ClientError
except ImportError:
    raise ImportError(
        "AWS SQS adapter requires 'aioboto3' package. "
        "Install it with: pip install amb-core[aws]"
    )


class AWSSQSBroker(BrokerAdapter):
    """
    AWS SQS broker adapter.
    
    This adapter uses AWS SQS queues for reliable message delivery.
    Supports both standard queues and FIFO queues for ordered processing.
    
    Example:
        ```python
        from amb_core.adapters import AWSSQSBroker
        
        broker = AWSSQSBroker(
            region_name="us-east-1",
            queue_url="https://sqs.us-east-1.amazonaws.com/123456789/my-queue"
        )
        await broker.connect()
        
        # Subscribe
        async def handler(msg):
            print(f"Received: {msg.payload}")
        
        await broker.subscribe("agent.tasks", handler)
        
        # Publish
        await broker.publish(Message(topic="agent.tasks", payload={"task": "analyze"}))
        ```
    """

    def __init__(
        self,
        region_name: str = "us-east-1",
        queue_url: Optional[str] = None,
        queue_name: str = "amb-messages",
        use_fifo: bool = False,
        aws_access_key_id: Optional[str] = None,
        aws_secret_access_key: Optional[str] = None
    ):
        """
        Initialize AWS SQS broker.
        
        Args:
            region_name: AWS region
            queue_url: Existing queue URL (optional)
            queue_name: Queue name to create/use
            use_fifo: Use FIFO queue for ordered delivery
            aws_access_key_id: AWS access key (uses env vars if not provided)
            aws_secret_access_key: AWS secret key (uses env vars if not provided)
        """
        self.region_name = region_name
        self.queue_url = queue_url
        self.queue_name = queue_name
        self.use_fifo = use_fifo
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        
        self._session = None
        self._sqs = None
        self._subscriptions: Dict[str, str] = {}  # subscription_id -> topic
        self._handlers: Dict[str, MessageHandler] = {}
        self._tasks: set = set()
        self._running = False
        self._topic_queues: Dict[str, str] = {}  # topic -> queue_url

    async def connect(self) -> None:
        """Connect to AWS SQS."""
        self._session = aioboto3.Session(
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            region_name=self.region_name
        )
        
        self._running = True
        
        # Get or create main queue
        async with self._session.client('sqs') as sqs:
            if not self.queue_url:
                queue_name = f"{self.queue_name}.fifo" if self.use_fifo else self.queue_name
                
                try:
                    # Try to get existing queue
                    response = await sqs.get_queue_url(QueueName=queue_name)
                    self.queue_url = response['QueueUrl']
                except ClientError:
                    # Create new queue
                    attributes = {}
                    if self.use_fifo:
                        attributes['FifoQueue'] = 'true'
                        attributes['ContentBasedDeduplication'] = 'true'
                    
                    response = await sqs.create_queue(
                        QueueName=queue_name,
                        Attributes=attributes
                    )
                    self.queue_url = response['QueueUrl']
        
        self._topic_queues['default'] = self.queue_url

    async def disconnect(self) -> None:
        """Disconnect from AWS SQS."""
        self._running = False
        
        # Cancel all tasks
        for task in self._tasks:
            if not task.done():
                task.cancel()
        
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        
        self._tasks.clear()
        self._session = None

    async def publish(self, message: Message, wait_for_confirmation: bool = False) -> Optional[str]:
        """
        Publish message to SQS queue.
        
        Args:
            message: Message to publish
            wait_for_confirmation: Wait for SQS acknowledgment (always true for SQS)
        
        Returns:
            Message ID
        """
        if not self._session:
            raise ConnectionError("Not connected to AWS SQS")
        
        async with self._session.client('sqs') as sqs:
            # Serialize message
            message_body = message.model_dump_json()
            
            # Build send parameters
            params = {
                'QueueUrl': self.queue_url,
                'MessageBody': message_body,
                'MessageAttributes': {
                    'topic': {
                        'DataType': 'String',
                        'StringValue': message.topic
                    },
                    'source': {
                        'DataType': 'String',
                        'StringValue': message.source
                    },
                    'message_id': {
                        'DataType': 'String',
                        'StringValue': message.id
                    }
                }
            }
            
            # FIFO queues require message group ID
            if self.use_fifo:
                params['MessageGroupId'] = message.topic.replace('/', '-')
                params['MessageDeduplicationId'] = message.id
            
            # Send message
            response = await sqs.send_message(**params)
            
            return response.get('MessageId', message.id)

    async def subscribe(self, topic: str, handler: MessageHandler) -> str:
        """
        Subscribe to messages on a topic.
        
        Starts polling the SQS queue for messages matching the topic.
        
        Args:
            topic: Topic to filter messages by
            handler: Message handler
        
        Returns:
            Subscription ID
        """
        subscription_id = str(uuid.uuid4())
        
        self._subscriptions[subscription_id] = topic
        self._handlers[topic] = handler
        
        # Start polling task
        task = asyncio.create_task(self._poll_task(subscription_id, topic, handler))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        
        return subscription_id

    async def _poll_task(self, subscription_id: str, topic: str, handler: MessageHandler):
        """Poll SQS queue for messages."""
        while self._running and subscription_id in self._subscriptions:
            try:
                async with self._session.client('sqs') as sqs:
                    # Receive messages
                    response = await sqs.receive_message(
                        QueueUrl=self.queue_url,
                        MaxNumberOfMessages=10,
                        WaitTimeSeconds=20,  # Long polling
                        MessageAttributeNames=['All']
                    )
                    
                    messages = response.get('Messages', [])
                    
                    for sqs_message in messages:
                        try:
                            # Parse message
                            body = sqs_message['Body']
                            amb_message = Message.model_validate_json(body)
                            
                            # Check topic filter
                            if amb_message.topic == topic or topic == "*":
                                await handler(amb_message)
                            
                            # Delete message after processing
                            await sqs.delete_message(
                                QueueUrl=self.queue_url,
                                ReceiptHandle=sqs_message['ReceiptHandle']
                            )
                            
                        except Exception as e:
                            print(f"Error handling SQS message: {e}")
                            # Leave message in queue for retry
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error polling SQS: {e}")
                await asyncio.sleep(1.0)

    async def unsubscribe(self, subscription_id: str) -> None:
        """
        Unsubscribe from messages.
        
        Args:
            subscription_id: Subscription ID
        """
        if subscription_id in self._subscriptions:
            topic = self._subscriptions[subscription_id]
            del self._subscriptions[subscription_id]
            
            if topic in self._handlers:
                del self._handlers[topic]

    async def request(self, message: Message, timeout: float = 30.0) -> Message:
        """
        Send request and wait for response.
        
        Uses a temporary response queue for the request-response pattern.
        
        Args:
            message: Request message
            timeout: Timeout in seconds
        
        Returns:
            Response message
        """
        if not self._session:
            raise ConnectionError("Not connected to AWS SQS")
        
        # Generate correlation ID
        if not message.correlation_id:
            message.correlation_id = str(uuid.uuid4())
        
        # Create response queue
        response_queue: asyncio.Queue = asyncio.Queue()
        
        async def response_handler(msg: Message):
            if msg.correlation_id == message.correlation_id:
                await response_queue.put(msg)
        
        # Subscribe to responses (using correlation ID as topic filter)
        response_topic = f"response.{message.correlation_id}"
        sub_id = await self.subscribe(response_topic, response_handler)
        
        try:
            # Set reply-to
            message.reply_to = response_topic
            
            # Publish request
            await self.publish(message, wait_for_confirmation=False)
            
            # Wait for response
            try:
                response = await asyncio.wait_for(response_queue.get(), timeout=timeout)
                return response
            except asyncio.TimeoutError:
                raise TimeoutError(f"No response received within {timeout} seconds")
        
        finally:
            await self.unsubscribe(sub_id)

    async def get_pending_messages(self, topic: str, limit: int = 10) -> List[Message]:
        """
        Peek at pending messages in the queue.
        
        Note: SQS doesn't support true peeking, so this uses visibility timeout
        and then returns messages to the queue.
        
        Args:
            topic: Topic to filter by
            limit: Maximum messages to retrieve
        
        Returns:
            List of messages
        """
        if not self._session:
            raise ConnectionError("Not connected to AWS SQS")
        
        messages = []
        
        async with self._session.client('sqs') as sqs:
            # Receive with short visibility timeout
            response = await sqs.receive_message(
                QueueUrl=self.queue_url,
                MaxNumberOfMessages=min(limit, 10),
                VisibilityTimeout=1,  # Short timeout so messages return to queue
                MessageAttributeNames=['All']
            )
            
            for sqs_message in response.get('Messages', []):
                try:
                    body = sqs_message['Body']
                    amb_message = Message.model_validate_json(body)
                    
                    if amb_message.topic == topic or topic == "*":
                        messages.append(amb_message)
                except Exception:
                    continue
        
        return messages

    async def health_check(self) -> bool:
        """Check if connected to AWS SQS."""
        if not self._session:
            return False
        
        try:
            async with self._session.client('sqs') as sqs:
                await sqs.get_queue_attributes(
                    QueueUrl=self.queue_url,
                    AttributeNames=['QueueArn']
                )
                return True
        except Exception:
            return False

    async def purge_queue(self) -> None:
        """Purge all messages from the queue."""
        if not self._session:
            raise ConnectionError("Not connected to AWS SQS")
        
        async with self._session.client('sqs') as sqs:
            await sqs.purge_queue(QueueUrl=self.queue_url)
