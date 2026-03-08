import cryptography
import langchain_core
import sys

def verify_installation():
    print("--- Agent Governance Toolkit: Installation Check ---")
    try:
        # Verifichiamo le dipendenze critiche aggiornate da Imran (Issue #103, #104)
        print(f"[OK] Cryptography version: {cryptography.__version__}")
        print(f"[OK] Langchain-Core version: {langchain_core.__version__}")
        print("[SUCCESS] Governance stack is ready.")
    except Exception as e:
        print(f"[ERROR] Stack verification failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    verify_installation()