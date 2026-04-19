import logging
import json
import os
import uuid
from logger_config import setup_logging, set_correlation_id

def verify_logging():
    setup_logging()
    logger = logging.getLogger("verification")

    # 1. Verify Correlation ID
    cid = set_correlation_id("test-cid-123")
    logger.info("Test message with correlation ID")

    # 2. Verify Redaction in Structured Data (INFO level payload)
    sensitive_data = {
        "user": "admin",
        "password": "secret_password_123",
        "nested": {
            "token": "sensitive-token-abc",
            "safe": "safe-value"
        }
    }
    logger.info("Test message with sensitive data", extra={"payload": sensitive_data})

    # 3. Verify Case-Insensitive Redaction
    logger.info("Case-insensitive redaction test", extra={"payload": {"Password": "leak", "TOKEN": "leak"}})

    # 4. Verify Standardized Activity Logging Format
    logger.info("Panorama Query", extra={
        "target": "Panorama",
        "action": "GET_INTERFACES",
        "duration_ms": 145,
        "status": 200
    })

    # 5. Verify String Leakage Redaction (f-string leak)
    password = "secret_password_fstring"
    logger.debug(f"Leaking password={password} in message string")

    # 6. Verify tuple args redaction
    logger.info("Payload in args: %s", {"password": "args_secret"})

    print("Verification logs generated. Checking logs/app.log...")

    with open("logs/app.log", "r") as f:
        lines = f.readlines()
        for line in lines:
            data = json.loads(line)
            print(f"Log: {data}")

            # Check Correlation ID
            if data["message"] == "Test message with correlation ID":
                assert data["correlation_id"] == "test-cid-123"
                print("✓ Correlation ID verified")

            # Check Redaction
            if data["message"] == "Test message with sensitive data":
                payload = data["payload"]
                assert payload["password"] == "[REDACTED]"
                assert payload["nested"]["token"] == "[REDACTED]"
                assert payload["nested"]["safe"] == "safe-value"
                print("✓ Nested Redaction verified")

            if data["message"] == "Case-insensitive redaction test":
                payload = data["payload"]
                assert payload["Password"] == "[REDACTED]"
                assert payload["TOKEN"] == "[REDACTED]"
                print("✓ Case-insensitive Redaction verified")

            # Check Structured Fields
            if data["message"] == "Panorama Query":
                assert data["target"] == "Panorama"
                assert data["action"] == "GET_INTERFACES"
                assert data["duration_ms"] == 145
                assert data["status"] == 200
                print("✓ Standardized Activity fields verified")

            # Check string redaction in message
            if "Leaking" in data["message"]:
                assert "password=[REDACTED]" in data["message"]
                print("✓ String leak redaction verified")

            # Check tuple args redaction
            if "Payload in args" in data["message"]:
                assert data["payload"]["password"] == "[REDACTED]"
                print("✓ Tuple args redaction verified")

if __name__ == "__main__":
    verify_logging()
