import logging
import json
import uuid
import time
import os
import re
from contextvars import ContextVar
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime

# Context variable to store the correlation ID globally for a request/task
correlation_id_ctx = ContextVar("correlation_id", default=None)

SENSITIVE_KEYS = {
    "password", "token", "secret", "auth_key", "pwd",
    "auth-token", "x-api-key", "community", "cookie",
    "api_key", "bearer", "authorization", "apikey", "refresh_token"
}

# Regex to find key=value or key:value patterns in strings, where key is in SENSITIVE_KEYS
# Matches 'password=secret', 'password: "secret"', etc.
SENSITIVE_RE = re.compile(
    rf"(?i)\b({'|'.join(re.escape(k) for k in SENSITIVE_KEYS)})\b\s*[:=]\s*([\"']?).+?\b\2(?=\s|,|$)",
    re.IGNORECASE
)

class Redactor:
    """Helper to redact sensitive information from strings and dictionaries."""

    @staticmethod
    def redact(data):
        if isinstance(data, dict):
            return {
                k: Redactor.redact(v) if k.lower() not in SENSITIVE_KEYS else "[REDACTED]"
                for k, v in data.items()
            }
        elif isinstance(data, list):
            return [Redactor.redact(item) for item in data]
        elif isinstance(data, str):
            # Use regex to redact common sensitive patterns in strings
            return SENSITIVE_RE.sub(r"\1=[REDACTED]", data)
        return data

class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as JSON, including correlation_id and handling redaction."""

    def format(self, record):
        # We redact the message string which might have sensitive info from f-strings
        message = record.getMessage()
        redacted_message = Redactor.redact(message)

        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redacted_message,
            "correlation_id": correlation_id_ctx.get() or record.__dict__.get("correlation_id", "N/A"),
        }

        # Add extra fields if they exist
        for key in ["target", "action", "status", "duration_ms", "payload"]:
            if hasattr(record, key):
                val = getattr(record, key)
                log_data[key] = Redactor.redact(val) if key in ("payload", "message") else val

        # Handle structured data in record.args if it's a dict/list/tuple (often used for payloads)
        if record.args:
            if isinstance(record.args, (dict, list)):
                log_data["payload"] = Redactor.redact(record.args)
            elif isinstance(record.args, tuple) and len(record.args) == 1 and isinstance(record.args[0], (dict, list)):
                log_data["payload"] = Redactor.redact(record.args[0])

        # If the message itself was a dict, redact it
        if isinstance(record.msg, (dict, list)):
            log_data["message"] = Redactor.redact(record.msg)

        return json.dumps(log_data)

class RedactingFormatter(logging.Formatter):
    """Standard formatter that redacts sensitive information for console output."""

    def format(self, record):
        # Add correlation_id to the record for the format string
        record.correlation_id = correlation_id_ctx.get() or "N/A"

        # We don't want to mutate the original record too much, but we must redact for security
        formatted = super().format(record)
        return Redactor.redact(formatted)

def setup_logging():
    """Centralized logging configuration."""
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)  # Capture everything, handlers will filter

    # Clear existing handlers
    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    # Console Handler (Level configurable via env, default INFO)
    console_level_name = os.getenv("CONSOLE_LOG_LEVEL", "INFO").upper()
    console_level = getattr(logging, console_level_name, logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_formatter = RedactingFormatter(
        "%(asctime)s [%(levelname)s] [%(correlation_id)s] %(name)s: %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # File Handler (DEBUG level, JSON)
    file_handler = TimedRotatingFileHandler(
        filename=os.path.join(log_dir, "app.log"),
        when="midnight",
        interval=1,
        backupCount=7
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(StructuredJsonFormatter())
    root_logger.addHandler(file_handler)

def get_logger(name):
    return logging.getLogger(name)

def set_correlation_id(cid=None):
    if cid is None:
        cid = str(uuid.uuid4())
    correlation_id_ctx.set(cid)
    return cid

def run_with_context(func, *args, **kwargs):
    """
    Wrapper to run a function while preserving the correlation_id context.
    Supports both:
    1. loop.run_in_executor(None, run_with_context(func, arg1))
    2. loop.run_in_executor(None, run_with_context(func), arg1)
    """
    cid = correlation_id_ctx.get()

    def wrapped(*extra_args, **extra_kwargs):
        token = correlation_id_ctx.set(cid)
        try:
            if args or kwargs:
                return func(*args, **kwargs)
            return func(*extra_args, **extra_kwargs)
        finally:
            correlation_id_ctx.reset(token)

    return wrapped
