# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Security utility functions for input validation and output sanitization.

This module provides centralized security functions to prevent:
- Command injection
- Secret leakage in logs
- Input validation bypasses
- Path traversal
"""

import re
import sys
import unicodedata
from typing import Any


# === DEBUG OUTPUT SANITIZATION ================================================

class SecureDebug:
    """
    Secure debug output that redacts sensitive information.

    Usage:
        SecureDebug.print("Safe message")
        SecureDebug.print_command(['yubico-piv-tool', '--key', 'secret'])
    """

    # Sensitive parameter names to redact
    SENSITIVE_PARAMS = {
        '--key', '--pin', '--management-key',
        '-k', '-p',
        'key', 'pin', 'management_key', 'password', 'secret'
    }

    # Sensitive data patterns to redact
    SENSITIVE_PATTERNS = [
        re.compile(r'--key=([0-9a-fA-F]{48})', re.IGNORECASE),
        re.compile(r'--pin=(\d{4,8})', re.IGNORECASE),
        re.compile(r'(shared_secret|derived_key|ephemeral_pub)\s*=\s*[0-9a-fA-F]+', re.IGNORECASE),
    ]

    @classmethod
    def sanitize_string(cls, text: str) -> str:
        """
        Sanitize a string by redacting sensitive information.

        Args:
            text: String that may contain sensitive data

        Returns:
            Sanitized string with secrets replaced by [REDACTED]
        """
        for pattern in cls.SENSITIVE_PATTERNS:
            text = pattern.sub(r'\1=[REDACTED]', text)
        return text

    @classmethod
    def sanitize_command(cls, cmd: list[str]) -> list[str]:
        """
        Sanitize command list for safe logging.

        Args:
            cmd: Command list that may contain sensitive parameters

        Returns:
            Sanitized command list with secrets redacted
        """
        sanitized = []
        skip_next = False

        for i, arg in enumerate(cmd):
            if skip_next:
                sanitized.append('[REDACTED]')
                skip_next = False
                continue

            # Check for --key=value format
            if '=' in arg:
                param_name = arg.split('=')[0]
                if any(param_name.endswith(s) for s in cls.SENSITIVE_PARAMS):
                    sanitized.append(f'{param_name}=[REDACTED]')
                    continue

            # Check for --key value format
            if arg in cls.SENSITIVE_PARAMS:
                sanitized.append(arg)
                skip_next = True
                continue

            sanitized.append(arg)

        return sanitized

    @classmethod
    def print(cls, message: str, file=None):
        """
        Print debug message to stderr with sensitive data redacted.

        Args:
            message: Debug message (may contain sensitive data)
            file: Output file (default: sys.stderr)
        """
        if file is None:
            file = sys.stderr

        sanitized = cls.sanitize_string(message)
        print(f'[DEBUG] {sanitized}', file=file)

    @classmethod
    def print_command(cls, cmd: list[str], file=None):
        """
        Print command for debugging with sensitive parameters redacted.

        Args:
            cmd: Command list
            file: Output file (default: sys.stderr)
        """
        if file is None:
            file = sys.stderr

        sanitized = cls.sanitize_command(cmd)
        print(f'[DEBUG] Command: {" ".join(sanitized)}', file=file)

    @classmethod
    def redact_bytes(cls, data: bytes, show_length: bool = True) -> str:
        """
        Redact byte data for logging.

        Args:
            data: Binary data to redact
            show_length: Whether to show data length

        Returns:
            Redacted representation
        """
        if show_length:
            return f'[REDACTED {len(data)} bytes]'
        return '[REDACTED]'


# === INPUT VALIDATION =========================================================

class InputValidator:
    """
    Input validation functions to prevent injection attacks.
    """

    # Valid PIV slots (hex strings)
    VALID_PIV_SLOTS = {
        '9a', '9c', '9d', '9e',  # Standard PIV slots
        '82', '83', '84', '85', '86', '87', '88', '89',  # Retired key slots
        '8a', '8b', '8c', '8d', '8e', '8f',
        '90', '91', '92', '93', '94', '95',
    }

    @staticmethod
    def validate_reader_name(reader: str) -> str:
        """
        Validate PC/SC reader name to prevent command injection.

        Args:
            reader: PC/SC reader name from user or device enumeration

        Returns:
            Validated reader name

        Raises:
            ValueError: If reader name is invalid
        """
        if not isinstance(reader, str):
            raise ValueError(f"Reader name must be a string, got {type(reader)}")

        # Check for control characters that could cause issues
        forbidden_chars = ['\n', '\r', '\0', '\t', ';', '|', '&', '$', '`']
        for char in forbidden_chars:
            if char in reader:
                raise ValueError(
                    f"Invalid character in reader name: {repr(char)}. "
                    f"Reader name may not contain control characters or shell metacharacters."
                )

        # Reasonable length limit (PC/SC spec allows up to ~200 chars)
        if len(reader) > 250:
            raise ValueError(f"Reader name too long: {len(reader)} characters (max 250)")

        if len(reader) == 0:
            raise ValueError("Reader name cannot be empty")

        return reader

    @staticmethod
    def validate_piv_slot(slot: str) -> str:
        """
        Validate PIV slot identifier.

        Args:
            slot: PIV slot identifier (hex string like '9e')

        Returns:
            Validated slot identifier

        Raises:
            ValueError: If slot is invalid
        """
        if not isinstance(slot, str):
            raise ValueError(f"PIV slot must be a string, got {type(slot)}")

        slot_lower = slot.lower()
        if slot_lower not in InputValidator.VALID_PIV_SLOTS:
            raise ValueError(
                f"Invalid PIV slot: {slot}. "
                f"Valid slots: {', '.join(sorted(InputValidator.VALID_PIV_SLOTS))}"
            )

        return slot_lower

    @staticmethod
    def validate_serial_number(serial: int) -> int:
        """
        Validate YubiKey serial number.

        Args:
            serial: YubiKey serial number

        Returns:
            Validated serial number

        Raises:
            ValueError: If serial is invalid
        """
        if not isinstance(serial, int):
            raise ValueError(f"Serial number must be an integer, got {type(serial)}")

        # YubiKey serial numbers are 32-bit unsigned integers
        if not 0 <= serial <= 0xFFFFFFFF:
            raise ValueError(
                f"Invalid serial number: {serial}. "
                f"Serial must be a 32-bit unsigned integer (0-4294967295)"
            )

        return serial

    @staticmethod
    def validate_x509_subject(subject: str) -> str:
        """
        Validate X.509 certificate subject string.

        Args:
            subject: X.509 subject (e.g., '/CN=test/O=example')

        Returns:
            Validated subject string

        Raises:
            ValueError: If subject contains invalid characters
        """
        if not isinstance(subject, str):
            raise ValueError(f"Subject must be a string, got {type(subject)}")

        # Check for forbidden characters that could cause issues
        forbidden_chars = ['\n', '\r', '\0', ';', '|', '&', '$', '`', '\\']
        for char in forbidden_chars:
            if char in subject:
                raise ValueError(
                    f"Invalid character in X.509 subject: {repr(char)}. "
                    f"Subject may not contain control characters or shell metacharacters."
                )

        # Basic format validation (should contain = for attributes)
        if '=' not in subject and subject != '/':
            raise ValueError(
                f"Invalid X.509 subject format: {subject}. "
                f"Expected format like '/CN=name/O=org' or just '/'"
            )

        # Reasonable length limit
        if len(subject) > 500:
            raise ValueError(f"X.509 subject too long: {len(subject)} characters (max 500)")

        return subject

    @staticmethod
    def validate_management_key(key: str) -> str:
        """
        Validate management key format.

        Args:
            key: Management key as hex string

        Returns:
            Validated and normalized management key (lowercase)

        Raises:
            ValueError: If key is invalid
        """
        if not isinstance(key, str):
            raise ValueError(f"Management key must be a string, got {type(key)}")

        # Remove spaces and dashes for user convenience
        key = key.replace(' ', '').replace('-', '').lower()

        # Check if it's valid hex
        try:
            bytes.fromhex(key)
        except ValueError as e:
            raise ValueError(
                f"Management key must be a hex string (0-9, a-f): {e}"
            ) from e

        # Check length (24 bytes = 48 hex chars for 3DES)
        if len(key) != 48:
            raise ValueError(
                f"Management key must be 48 hex characters (24 bytes), got {len(key)}"
            )

        return key

    @staticmethod
    def validate_blob_name(name: str) -> str:
        """
        Validate and normalize blob name.

        Args:
            name: Blob name from user

        Returns:
            Validated and normalized blob name

        Raises:
            ValueError: If name is invalid
        """
        if not isinstance(name, str):
            raise ValueError(f"Blob name must be a string, got {type(name)}")

        # Normalize Unicode to NFC form to prevent homograph attacks
        # e.g., "test" (Latin) vs "тest" (Cyrillic т) would be different
        name = unicodedata.normalize('NFC', name)

        # Check for control characters
        for char in name:
            category = unicodedata.category(char)
            if category.startswith('C'):  # Control characters
                raise ValueError(
                    f"Blob name contains control character: U+{ord(char):04X}. "
                    f"Control characters are not allowed."
                )

        # Check length after UTF-8 encoding
        name_bytes = name.encode('utf-8')
        if len(name_bytes) == 0:
            raise ValueError("Blob name cannot be empty")

        if len(name_bytes) > 255:
            raise ValueError(
                f"Blob name too long: {len(name_bytes)} bytes after UTF-8 encoding (max 255)"
            )

        return name

    @staticmethod
    def sanitize_error_message(message: str, debug: bool = False) -> str:
        """
        Sanitize error messages to prevent information leakage.

        Args:
            message: Original error message
            debug: Whether debug mode is enabled

        Returns:
            Sanitized error message (detailed if debug=True, generic otherwise)
        """
        if debug:
            # In debug mode, show full message but redact secrets
            return SecureDebug.sanitize_string(message)
        else:
            # In production mode, provide generic error
            # Keep only the first line and make it generic
            first_line = message.split('\n')[0]
            if 'magic' in first_line.lower():
                return "Store corruption detected. Use --debug for details."
            elif 'authentication' in first_line.lower():
                return "Authentication failed. Check your credentials."
            elif 'verification' in first_line.lower():
                return "Verification failed. Operation aborted."
            else:
                return "Operation failed. Use --debug for details."


# === AUDIT LOGGING ============================================================

class AuditLogger:
    """
    Security audit logging for compliance and forensics.

    Logs security-relevant events without exposing sensitive data.
    """

    @staticmethod
    def log_event(event_type: str, details: dict[str, Any], file=None):
        """
        Log a security event.

        Args:
            event_type: Type of event (e.g., 'pin_verify', 'blob_create')
            details: Event details (sensitive data will be redacted)
            file: Output file (default: sys.stderr)
        """
        if file is None:
            file = sys.stderr

        import datetime
        timestamp = datetime.datetime.now().isoformat()

        # Redact sensitive fields
        safe_details = {}
        for key, value in details.items():
            if any(sensitive in key.lower() for sensitive in ['pin', 'key', 'secret', 'password']):
                safe_details[key] = '[REDACTED]'
            elif isinstance(value, bytes):
                safe_details[key] = f'<{len(value)} bytes>'
            else:
                safe_details[key] = str(value)

        # Format log entry
        details_str = ', '.join(f'{k}={v}' for k, v in safe_details.items())
        log_line = f"[AUDIT] {timestamp} {event_type}: {details_str}"

        print(log_line, file=file)

    @staticmethod
    def log_pin_verification(reader: str, success: bool):
        """Log PIN verification attempt."""
        AuditLogger.log_event('pin_verification', {
            'reader': reader,
            'success': success,
        })

    @staticmethod
    def log_blob_operation(operation: str, blob_name: str, encrypted: bool, reader: str):
        """Log blob operation (create, fetch, delete)."""
        AuditLogger.log_event(f'blob_{operation}', {
            'blob_name': blob_name,
            'encrypted': encrypted,
            'reader': reader,
        })

    @staticmethod
    def log_management_key_usage(reader: str, operation: str):
        """Log management key usage."""
        AuditLogger.log_event('management_key_usage', {
            'reader': reader,
            'operation': operation,
        })
