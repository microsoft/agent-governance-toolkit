import hashlib
import hmac

class AgenticTrustProof:
    """
    Cryptographic proof of authorization for agent workflows.
    Ensures that agent actions are verifiable and tamper-proof.
    Addresses issue #4203.
    """
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode()

    def generate_proof(self, agent_id: str, task_id: str, action: str) -> str:
        message = f"{agent_id}:{task_id}:{action}".encode()
        return hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()

    def verify_proof(self, agent_id: str, task_id: str, action: str, proof: str) -> bool:
        expected_proof = self.generate_proof(agent_id, task_id, action)
        return hmac.compare_digest(expected_proof, proof)
