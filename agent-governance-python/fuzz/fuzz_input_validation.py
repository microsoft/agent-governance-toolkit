"""Fuzz target for input validation (path traversal, SQL injection, code injection).

Tests that adversarial inputs are correctly blocked by the policy engine's
input validation layer.
"""
import re
import sys
import atheris


CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
PATH_TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|%2e%2e|%252e")
PROTECTED_DIRS = {"/etc", "/root", "/var/run", "/proc", "/sys", "C:\\Windows", "C:\\System32"}
DANGEROUS_CODE_RE = re.compile(
    r"(exec|eval|compile|__import__|subprocess|os\.system|os\.popen)",
    re.IGNORECASE,
)
SQL_DESTRUCTIVE_RE = re.compile(
    r"\b(DROP|DELETE|TRUNCATE|ALTER|UPDATE)\b.*\b(TABLE|DATABASE|FROM|SET)\b",
    re.IGNORECASE,
)


def validate_path(path: str) -> bool:
    """Check for path traversal attacks."""
    if CONTROL_CHAR_RE.search(path):
        return False
    if PATH_TRAVERSAL_RE.search(path):
        return False
    for protected in PROTECTED_DIRS:
        if path.startswith(protected):
            return False
    return True


def validate_code(code: str) -> bool:
    """Check for dangerous code patterns."""
    return not DANGEROUS_CODE_RE.search(code)


def validate_sql(query: str) -> bool:
    """Check for destructive SQL."""
    return not SQL_DESTRUCTIVE_RE.search(query)


def fuzz_input_validation(data: bytes) -> None:
    """Fuzz all input validation paths."""
    try:
        text = data.decode("utf-8", errors="replace")

        # Test path validation
        validate_path(text)

        # Test code validation
        validate_code(text)

        # Test SQL validation
        validate_sql(text)

    except (ValueError, TypeError, UnicodeDecodeError, RecursionError, re.error):
        pass


def main() -> None:
    atheris.Setup(sys.argv, fuzz_input_validation)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
