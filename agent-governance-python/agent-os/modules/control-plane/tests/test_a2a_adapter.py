# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for the A2A Adapter
"""

import unittest
import json
from datetime import datetime
from agent_control_plane import (
    AgentControlPlane,
    A2AAdapter,
    A2AAgent,
    create_governed_a2a_agent,
    ActionType,
    PermissionLevel,
)


class TestA2AAdapter(unittest.TestCase):
    """Test suite for A2A Adapter"""
    
    def test_create_adapter(self):
        """Test creating an A2A adapter"""
        control_plane = AgentControlPlane()
        
        permissions = {
            ActionType.WORKFLOW_TRIGGER: PermissionLevel.READ_WRITE,
        }
        agent_context = control_plane.create_agent("a2a-test", permissions)
        
        agent_card = {
            "name": "Test Agent",
            "capabilities": []
        }
        
        adapter = A2AAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            agent_card=agent_card
        )
        
        self.assertIsNotNone(adapter)
        self.assertEqual(adapter.agent_context.agent_id, "a2a-test")
    
    def test_register_capability(self):
        """Test registering a capability"""
        control_plane = AgentControlPlane()
        permissions = {
            ActionType.WORKFLOW_TRIGGER: PermissionLevel.READ_WRITE,
        }
        agent_context = control_plane.create_agent("cap-test", permissions)
        
        adapter = A2AAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            agent_card={"name": "Test"}
        )
        
        def handle_capability(params):
            return {"result": "success"}
        
        adapter.register_capability("test_capability", handle_capability)
        
        self.assertIn("test_capability", adapter.capabilities)
    
    def test_get_agent_card(self):
        """Test getting the Agent Card"""
        control_plane = AgentControlPlane()
        permissions = {}
        agent_context = control_plane.create_agent("card-test", permissions)
        
        agent_card = {
            "name": "Test Agent",
            "description": "A test agent",
            "version": "1.0.0",
            "capabilities": ["test"]
        }
        
        adapter = A2AAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            agent_card=agent_card
        )
        
        card = adapter.get_agent_card()
        
        self.assertEqual(card["name"], "Test Agent")
        self.assertEqual(card["agent_id"], "card-test")
        self.assertIn("capabilities", card)
    
    def test_discovery_message(self):
        """Test handling discovery message"""
        control_plane = AgentControlPlane()
        permissions = {}
        agent_context = control_plane.create_agent("disc-test", permissions)
        
        adapter = A2AAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            agent_card={"name": "Discovery Test"}
        )
        
        message = {
            "id": "msg-1",
            "type": "discovery",
            "from": "other-agent",
            "payload": {}
        }
        
        response = adapter.handle_message(message, "other-agent")
        
        self.assertEqual(response["type"], "response")
        self.assertIn("agent_card", response["payload"])
    
    def test_handshake_message(self):
        """Test handling handshake message"""
        control_plane = AgentControlPlane()
        permissions = {}
        agent_context = control_plane.create_agent("shake-test", permissions)
        
        adapter = A2AAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            agent_card={"name": "Handshake Test"}
        )
        
        message = {
            "id": "msg-2",
            "type": "handshake",
            "from": "peer-agent",
            "payload": {
                "agent_card": {"name": "Peer Agent"}
            }
        }
        
        response = adapter.handle_message(message, "peer-agent")
        
        self.assertEqual(response["type"], "response")
        self.assertEqual(response["payload"]["status"], "connected")
        
        # Verify peer was registered
        self.assertIn("peer-agent", adapter.peer_agents)
    
    def test_task_delegation(self):
        """Test handling task delegation"""
        control_plane = AgentControlPlane()
        permissions = {
            ActionType.WORKFLOW_TRIGGER: PermissionLevel.READ_WRITE,
        }
        agent_context = control_plane.create_agent("deleg-test", permissions)
        
        adapter = A2AAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            agent_card={"name": "Delegator"}
        )
        
        message = {
            "id": "msg-3",
            "type": "task_delegation",
            "from": "delegator",
            "payload": {
                "target_agent": "specialist",
                "task_type": "analysis",
                "parameters": {}
            }
        }
        
        response = adapter.handle_message(message, "delegator")
        
        self.assertEqual(response["type"], "response")
        self.assertEqual(response["payload"]["status"], "delegated")
    
    def test_query_message(self):
        """Test handling query message"""
        control_plane = AgentControlPlane()
        permissions = {
            ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        }
        agent_context = control_plane.create_agent("query-test", permissions)
        
        adapter = A2AAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            agent_card={"name": "Query Handler"}
        )
        
        message = {
            "id": "msg-4",
            "type": "query",
            "from": "querier",
            "payload": {
                "query_type": "database_query",
                "parameters": {"table": "users"}
            }
        }
        
        response = adapter.handle_message(message, "querier")
        
        self.assertEqual(response["type"], "response")
        self.assertIn("data", response["payload"])
    
    def test_custom_capability_mapping(self):
        """Test custom capability to ActionType mapping"""
        control_plane = AgentControlPlane()
        permissions = {}
        agent_context = control_plane.create_agent("map-test", permissions)
        
        custom_mapping = {
            "custom_capability": ActionType.FILE_READ,
        }
        
        adapter = A2AAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            agent_card={"name": "Mapper"},
            capability_mapping=custom_mapping
        )
        
        self.assertIn("custom_capability", adapter.capability_mapping)
    
    def test_a2a_agent_creation(self):
        """Test creating an A2A agent"""
        control_plane = AgentControlPlane()
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
        
        a2a_agent = create_governed_a2a_agent(
            control_plane=control_plane,
            agent_id="agent-test",
            agent_card={"name": "Test Agent"},
            permissions=permissions
        )
        
        self.assertIsNotNone(a2a_agent)
        self.assertEqual(a2a_agent.agent_id, "agent-test")
    
    def test_send_task_request(self):
        """Test sending a task request"""
        control_plane = AgentControlPlane()
        permissions = {}
        agent_context = control_plane.create_agent("sender-test", permissions)
        
        a2a_agent = A2AAgent(
            agent_id="sender",
            control_plane=control_plane,
            agent_context=agent_context
        )
        
        message = a2a_agent.send_task_request(
            to_agent="receiver",
            task_type="process_data",
            parameters={"data": [1, 2, 3]}
        )
        
        self.assertEqual(message["type"], "task_request")
        self.assertEqual(message["from"], "sender")
        self.assertEqual(message["to"], "receiver")
        self.assertIn("payload", message)
    
    def test_map_capability_to_action(self):
        """Test capability name to ActionType mapping"""
        control_plane = AgentControlPlane()
        permissions = {}
        agent_context = control_plane.create_agent("cap-map-test", permissions)
        
        adapter = A2AAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            agent_card={"name": "Mapper"}
        )
        
        # Test various capability names
        self.assertEqual(
            adapter._map_capability_to_action("read_file"),
            ActionType.FILE_READ
        )
        self.assertEqual(
            adapter._map_capability_to_action("execute_task"),
            ActionType.CODE_EXECUTION
        )
        self.assertEqual(
            adapter._map_capability_to_action("database_query"),
            ActionType.DATABASE_QUERY
        )
    
    def test_discover_agents(self):
        """Test discovering peer agents"""
        control_plane = AgentControlPlane()
        permissions = {}
        agent_context = control_plane.create_agent("discover-test", permissions)
        
        adapter = A2AAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            agent_card={"name": "Discoverer"}
        )
        
        # Simulate handshake with peer agents
        adapter.peer_agents["peer1"] = {"name": "Peer 1"}
        adapter.peer_agents["peer2"] = {"name": "Peer 2"}
        
        discovered = adapter.discover_agents()
        
        self.assertEqual(len(discovered), 2)
        self.assertTrue(any(a["agent_id"] == "peer1" for a in discovered))
    
    def test_negotiate_message(self):
        """Test handling negotiate message"""
        control_plane = AgentControlPlane()
        permissions = {}
        agent_context = control_plane.create_agent("neg-test", permissions)
        
        adapter = A2AAdapter(
            control_plane=control_plane,
            agent_context=agent_context,
            agent_card={"name": "Negotiator"}
        )
        
        message = {
            "id": "msg-5",
            "type": "negotiate",
            "from": "negotiator",
            "payload": {
                "parameters": {"timeout": 30, "priority": "high"}
            }
        }
        
        response = adapter.handle_message(message, "negotiator")
        
        self.assertEqual(response["type"], "response")
        self.assertEqual(response["payload"]["status"], "accepted")


if __name__ == "__main__":
    unittest.main()
