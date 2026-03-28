# test_cli_run.py
from agent_os.policies.cli import success, error, warn, policy_violation, passed_check

def main():
    print("=== Testing CLI functions with colored output ===\n")

    print("1️⃣  success():")
    success("This is a success message")

    print("\n2️⃣  error():")
    error("This is an error message")

    print("\n3️⃣  warn():")
    warn("This is a warning message")

    print("\n4️⃣  policy_violation():")
    policy_violation("Policy violation detected!")

    print("\n5️⃣  passed_check():")
    passed_check("Test passed successfully!")

    print("\n=== Done testing CLI functions ===")

if __name__ == "__main__":
    main()
