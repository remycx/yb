# Security Analysis Report - YubiKey Blob Store (yb)

**Analysis Date:** 2025-12-02
**Repository:** https://github.com/douzebis/yb
**Analyzed Version:** Current main branch

## Executive Summary

This security analysis examined the YubiKey blob storage tool (yb), which provides encrypted storage of small binary blobs using YubiKey's PIV application. The analysis covered authentication mechanisms, input validation, cryptographic implementations, dependency security, command injection risks, secrets management, and deployment security.

**Overall Security Posture:** GOOD with some areas requiring attention

### Key Findings Summary
- ✅ **Strong cryptographic implementation** using industry-standard algorithms
- ✅ **Excellent default credential detection** preventing insecure deployments
- ✅ **Good PIN/authentication handling** using hardware-backed security
- ⚠️ **Command injection risks** in subprocess calls (MEDIUM severity)
- ⚠️ **Missing input validation** in some areas (LOW-MEDIUM severity)
- ⚠️ **Secrets exposure** in debug output and error messages (MEDIUM severity)
- ⚠️ **No dependency pinning** increasing supply chain risks (MEDIUM severity)

---

## 1. Authentication and Authorization

### ✅ Strengths

#### Default Credential Detection (src/yb/auxiliaries.py:202-277)
**EXCELLENT IMPLEMENTATION**

The tool implements proactive default credential detection using YubiKey's GET_METADATA command (firmware 5.3+):

```python
def check_for_default_credentials(reader, piv, allow_defaults=False):
    # Checks PIN, PUK, and Management Key for defaults
    # - PIN default: 123456
    # - PUK default: 12345678
    # - Management Key default: 010203...
```

**Benefits:**
- Prevents accidental use of insecure default credentials
- Does NOT consume retry attempts (safe operation)
- Clear error messages with remediation steps
- Can be overridden with `--allow-defaults` flag for testing

**Location:** src/yb/main.py:310-317

#### PIN-Protected Management Key Mode (src/yb/auxiliaries.py:429-534)
**WELL IMPLEMENTED**

Supports secure PIN-protected management key storage:
- Management key encrypted and stored in PRINTED object (0x5FC109)
- Only accessible after PIN verification
- Rejects deprecated PIN-derived mode (insecure)

**Location:** src/yb/auxiliaries.py:386-427

### ⚠️ Concerns

#### No Rate Limiting on PIN Attempts
**SEVERITY: LOW**

The tool does not implement application-level rate limiting on PIN attempts. However, this is partially mitigated by:
- YubiKey hardware enforces retry limits (typically 3 attempts)
- PIN lockout handled by YubiKey firmware
- PUK can be used to reset PIN

**Recommendation:** Document the PIN retry behavior and lockout recovery process in user documentation.

---

## 2. Input Validation and Sanitization

### ✅ Strengths

#### Blob Name Validation (src/yb/orchestrator.py:50-51, 164-165)
```python
if len(name) == 0 or len(name) > 255:
    raise ValueError(f"Invalid name length: {len(name)} (must be 1-255)")
```

#### TLV Parsing with Safety Checks (src/yb/auxiliaries.py:52-104)
Comprehensive bounds checking on TLV data parsing with proper error handling.

#### Management Key Validation (src/yb/main.py:73-102)
```python
def validate_management_key(key: str) -> str:
    # Validates hex format and length (48 chars = 24 bytes)
    # Rejects invalid characters
```

### ⚠️ Concerns

#### 1. **Insufficient Subject String Validation** (MEDIUM severity)
**Location:** src/yb/crypto.py:27-48

```python
def generate_certificate(cls, reader, slot, subject, pin=None, management_key=None):
    subject += '/'  # Simple string concatenation
    # Passed directly to subprocess without validation
```

**Issue:** The `subject` parameter is used in X.509 certificate generation without proper validation. Special characters could potentially cause issues or be misinterpreted.

**Attack Vector:**
```bash
yb format --subject "CN=test\n--malicious-flag"
```

**Recommendation:**
```python
def validate_x509_subject(subject: str) -> str:
    """Validate X.509 subject string."""
    # Check for forbidden characters
    forbidden_chars = ['\n', '\r', '\0', ';', '|', '&']
    if any(char in subject for char in forbidden_chars):
        raise ValueError(f"Invalid characters in subject: {subject}")

    # Validate format (should be /CN=.../O=... format)
    if not subject.startswith('/') and '=' not in subject:
        raise ValueError(f"Invalid subject format: {subject}")

    return subject
```

#### 2. **Integer Overflow Risks in Serialization** (LOW severity)
**Location:** src/yb/store.py:324-347, 490-527

Various integer fields are validated against byte size limits:
```python
if not 0 <= object_age < 256**OBJECT_AGE_S:
    raise ValueError
```

**Issue:** While validation exists, there's no explicit protection against integer overflow in calculations.

**Recommendation:** Use Python's arbitrary precision integers safely, add explicit overflow checks in critical paths.

#### 3. **No Unicode Normalization on Blob Names** (LOW severity)
**Location:** src/yb/orchestrator.py:50-51

```python
if len(name) == 0 or len(name) > 255:
    raise ValueError(f"Invalid name length: {len(name)} (must be 1-255)")
```

**Issue:** Unicode characters are accepted but not normalized. This could lead to:
- Homograph attacks (look-alike names)
- UTF-8 encoding issues
- Inconsistent name matching

**Example Attack:**
```python
# These look the same but are different:
name1 = "test"  # Latin 't'
name2 = "тest"  # Cyrillic 'т' (U+0442)
```

**Recommendation:**
```python
import unicodedata

def validate_blob_name(name: str) -> str:
    """Validate and normalize blob name."""
    # Normalize to NFC form
    name = unicodedata.normalize('NFC', name)

    # Check length after encoding
    name_bytes = name.encode('utf-8')
    if len(name_bytes) == 0 or len(name_bytes) > 255:
        raise ValueError(f"Invalid name length: {len(name_bytes)} bytes")

    # Reject control characters
    if any(unicodedata.category(c).startswith('C') for c in name):
        raise ValueError("Control characters not allowed in blob names")

    return name
```

---

## 3. Cryptographic Implementation

### ✅ Strengths

#### Strong Cryptographic Algorithms
**EXCELLENT CHOICES**

All algorithms follow current best practices:

1. **Key Exchange:** ECDH with P-256 (SECP256R1) curve
2. **Key Derivation:** HKDF-SHA256 with context string `b'hybrid-encryption'`
3. **Encryption:** AES-256-CBC with PKCS7 padding
4. **Ephemeral Keys:** New EC key pair generated per operation

**Location:** src/yb/crypto.py:260-303, 305-410

#### Proper IV Generation
```python
iv = os.urandom(16)  # Cryptographically secure random IV
```

#### Secure Key Derivation
```python
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'hybrid-encryption',
    backend=default_backend(),
).derive(shared_secret)
```

### ⚠️ Concerns

#### 1. **No Authentication/Integrity Protection** (HIGH severity)
**Location:** src/yb/crypto.py:260-303

**Issue:** The encryption uses AES-CBC without message authentication (MAC). This is vulnerable to:
- Padding oracle attacks
- Ciphertext manipulation
- Chosen-ciphertext attacks

**Current Implementation:**
```
[Ephemeral Public Key (65 bytes)] || [IV (16 bytes)] || [Ciphertext]
```

**Vulnerability:** An attacker with write access to the YubiKey could:
1. Modify ciphertext blocks
2. Flip bits in encrypted data
3. Potentially decrypt data through padding oracle

**Recommendation:** Use authenticated encryption (AEAD):

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hybrid_encrypt(cls, blob: bytes, peer_public_key):
    # Generate ephemeral key pair (same as before)
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Perform ECDH (same as before)
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), peer_public_key)

    # Derive key (same as before)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'hybrid-encryption',
        backend=default_backend(),
    ).derive(shared_secret)

    # Use AES-GCM instead of AES-CBC
    nonce = os.urandom(12)  # GCM uses 96-bit nonce
    aesgcm = AESGCM(derived_key)

    # Encrypt with authentication
    # AAD (Additional Authenticated Data) includes ephemeral public key
    ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    ciphertext = aesgcm.encrypt(nonce, blob, ephemeral_pub_bytes)

    # Return: ephemeral_pub || nonce || ciphertext (includes auth tag)
    return ephemeral_pub_bytes + nonce + ciphertext
```

**Impact:** CRITICAL for security. Without MAC:
- Data integrity cannot be verified
- Active attacks possible
- Compliance issues (most security standards require AEAD)

#### 2. **PKCS7 Padding Oracle Potential** (MEDIUM severity)
**Location:** src/yb/crypto.py:403-404

```python
unpadder = PKCS7(128).unpadder()
plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
```

**Issue:** If padding errors are distinguishable from other decryption errors, timing attacks could enable plaintext recovery.

**Recommendation:**
1. Switch to AES-GCM (eliminates padding)
2. If keeping CBC, ensure constant-time padding validation and uniform error handling

#### 3. **No Key Rotation Mechanism** (LOW severity)
**Location:** src/yb/crypto.py

**Issue:** Once a key pair is generated in slot 0x9e, there's no built-in mechanism to rotate it. Compromised keys cannot be easily replaced.

**Recommendation:**
- Add `yb rotate-key` command
- Support multiple key slots with versioning
- Maintain backward compatibility for old blobs

---

## 4. Command Injection Vulnerabilities

### ⚠️ **HIGH RISK AREAS**

Multiple subprocess calls with potential command injection vectors:

#### 1. **Reader Name Injection** (HIGH severity)
**Location:** src/yb/piv.py:323-345, src/yb/crypto.py:59-68

```python
cmd = [
    'yubico-piv-tool',
    '--reader', str(reader),  # ⚠️ User-controlled reader name
    '--action', 'generate',
    # ...
]
subprocess.run(cmd, capture_output=True)
```

**Vulnerability:** The `reader` parameter is controlled by the user via `--reader` flag or device selection. While passed as a list (preventing shell injection), malicious reader names could cause unexpected behavior.

**Attack Vector:**
```bash
# Hypothetical attack (depends on yubico-piv-tool parsing)
yb --reader "Yubico\nDevice'; echo 'malicious'; '" store myfile
```

**Current Mitigation:** Using list arguments instead of shell=True prevents basic shell injection.

**Recommendation:**
```python
def validate_reader_name(reader: str) -> str:
    """Validate PC/SC reader name."""
    # Reader names should not contain control characters
    if any(c in reader for c in ['\n', '\r', '\0', '\t']):
        raise ValueError(f"Invalid reader name: {repr(reader)}")

    # Reasonable length limit (PC/SC spec allows up to 200 chars)
    if len(reader) > 200:
        raise ValueError(f"Reader name too long: {len(reader)} chars")

    return reader
```

**Apply at:** src/yb/main.py:204-217 (before storing in context)

#### 2. **Slot Parameter Injection** (MEDIUM severity)
**Location:** src/yb/crypto.py:59-68, src/yb/piv.py:323-345

```python
cmd = [
    'yubico-piv-tool',
    '--reader', reader,
    '--slot', slot,  # ⚠️ Passed from code but should validate format
    # ...
]
```

**Issue:** While `slot` is typically hardcoded (e.g., '9e'), it's passed as a string parameter. Invalid slot values could cause unexpected behavior.

**Recommendation:**
```python
VALID_PIV_SLOTS = {
    '9a', '9c', '9d', '9e',  # Standard PIV slots
    '82', '83', '84', '85', '86', '87', '88', '89',  # Retired slots
    '8a', '8b', '8c', '8d', '8e', '8f',
    '90', '91', '92', '93', '94', '95',
}

def validate_piv_slot(slot: str) -> str:
    """Validate PIV slot identifier."""
    if slot not in VALID_PIV_SLOTS:
        raise ValueError(f"Invalid PIV slot: {slot}")
    return slot
```

#### 3. **Management Key Injection** (LOW severity)
**Location:** src/yb/piv.py:329-330

```python
if management_key is not None:
    cmd.append(f'--key={management_key}')  # ⚠️ User-provided hex string
```

**Current Protection:** `validate_management_key()` checks hex format and length (src/yb/main.py:73-102)

**Residual Risk:** While validated, the key is passed in command arguments which may be visible in process listings.

**Recommendation:** Consider using stdin or environment variables for key passing:
```python
# Pass via stdin instead of command-line
result = subprocess.run(
    cmd,
    input=management_key.encode(),
    capture_output=True,
    # ...
)
```

#### 4. **PKCS#11 Token Label Injection** (MEDIUM severity)
**Location:** src/yb/crypto.py:464-465

```python
token_label = f"YubiKey PIV #{serial}"  # ⚠️ Serial from hardware

cmd = [
    'pkcs11-tool',
    '--token-label', token_label,  # ⚠️ Includes serial number
    # ...
]
```

**Issue:** While `serial` comes from the YubiKey hardware (trusted source), it's an integer that could theoretically be manipulated in testing scenarios.

**Recommendation:**
```python
def validate_serial_number(serial: int) -> int:
    """Validate YubiKey serial number."""
    # YubiKey serial numbers are 32-bit unsigned integers
    if not 0 <= serial <= 0xFFFFFFFF:
        raise ValueError(f"Invalid serial number: {serial}")
    return serial

# Then in token label construction:
token_label = f"YubiKey PIV #{validate_serial_number(serial)}"
```

### ✅ Mitigations in Place

1. **List-based subprocess calls** - All `subprocess.run()` calls use list arguments, NOT shell strings
2. **No shell=True** - Prevents shell injection via metacharacters
3. **Input validation** - Management key validation exists

---

## 5. Dependency Security

### ⚠️ **Critical Issues**

#### 1. **No Dependency Pinning** (HIGH severity)
**Location:** pyproject.toml:14-18

```toml
dependencies = [
  "click",
  "PyYAML",
  "cryptography"
]
```

**Issue:** No version constraints on dependencies. This creates:
- **Supply chain attacks:** Compromised package updates auto-installed
- **Breaking changes:** Untested versions could break functionality
- **Vulnerability exposure:** Known vulnerabilities might be introduced

**Example Attack Scenario:**
1. Attacker compromises PyPI account for `click`
2. Pushes malicious version 9.0.0
3. Users run `pip install yb` and get malicious code
4. Credentials/keys exfiltrated

**Recommendation:**

```toml
dependencies = [
  "click>=8.0.0,<9.0.0",
  "PyYAML>=6.0,<7.0",
  "cryptography>=42.0.0,<43.0.0"
]

[project.optional-dependencies]
dev = [
  "pytest>=7.0.0,<8.0.0",
  "pytest-cov>=4.0.0,<5.0.0",
]
```

**Also add:** `requirements-lock.txt` for reproducible builds:
```bash
# Generate locked requirements
pip-compile pyproject.toml -o requirements-lock.txt

# Install from locked file
pip install -r requirements-lock.txt
```

#### 2. **External Tool Dependencies Not Validated** (MEDIUM severity)

The tool depends on external binaries:
- `yubico-piv-tool` (PIV operations)
- `pkcs11-tool` (PKCS#11 operations)
- `openssl` (certificate parsing)
- `ykman` (device enumeration)

**Issues:**
- No version checking
- No binary integrity verification
- PATH injection possible
- Behavior varies across versions

**Recommendation:**

```python
import shutil
import subprocess

REQUIRED_TOOLS = {
    'yubico-piv-tool': {
        'min_version': '2.3.0',
        'check_cmd': ['yubico-piv-tool', '--version'],
    },
    'pkcs11-tool': {
        'min_version': '0.22.0',
        'check_cmd': ['pkcs11-tool', '--version'],
    },
    'openssl': {
        'min_version': '1.1.1',
        'check_cmd': ['openssl', 'version'],
    },
}

def validate_external_dependencies():
    """Validate external tool dependencies."""
    for tool, config in REQUIRED_TOOLS.items():
        # Check if tool exists
        tool_path = shutil.which(tool)
        if not tool_path:
            raise RuntimeError(
                f"Required tool '{tool}' not found in PATH. "
                f"Please install version >= {config['min_version']}"
            )

        # Check version
        try:
            result = subprocess.run(
                config['check_cmd'],
                capture_output=True,
                text=True,
                timeout=5
            )
            version_output = result.stdout + result.stderr
            # Parse and validate version
            # (implementation depends on tool output format)
        except Exception as e:
            print(f"Warning: Could not verify {tool} version: {e}", file=sys.stderr)

# Call during startup
if __name__ == "__main__":
    validate_external_dependencies()
    cli()
```

#### 3. **No Dependency Vulnerability Scanning** (MEDIUM severity)

**Recommendation:** Add to CI/CD pipeline:

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Safety check
        run: |
          pip install safety
          safety check --file requirements-lock.txt

      - name: Run Bandit
        run: |
          pip install bandit
          bandit -r src/ -f json -o bandit-report.json

      - name: Run pip-audit
        run: |
          pip install pip-audit
          pip-audit -r requirements-lock.txt
```

---

## 6. Secrets Management

### ⚠️ **Significant Issues**

#### 1. **Secrets in Debug Output** (HIGH severity)
**Location:** src/yb/crypto.py:71-90, 335-387

```python
if debug:
    print(f'[DEBUG] Crypto: Full command ({len(cmd)} args):', file=sys.stderr)
    for i, arg in enumerate(cmd):
        print(f'[DEBUG] Crypto:   [{i}] = {repr(arg)}', file=sys.stderr)
        # ⚠️ This outputs the --key=<management_key> in plaintext!
```

**Attack Vector:**
```bash
# Attacker tricks user into running with --debug
yb --debug --key=0102030405060708... store myfile 2>&1 | attacker-logger

# Management key and PIN exposed in debug output
```

**Impact:**
- Management keys logged to stderr
- PINs may be visible in debug output
- Ephemeral key material exposed
- Shared secrets printed in hex

**Recommendation:**

```python
SENSITIVE_PARAMS = {'--key', '--pin', '--management-key'}

def sanitize_command_for_logging(cmd: list[str]) -> list[str]:
    """Sanitize command for safe logging."""
    sanitized = []
    skip_next = False

    for i, arg in enumerate(cmd):
        if skip_next:
            sanitized.append('[REDACTED]')
            skip_next = False
            continue

        # Check for --key=value format
        if any(arg.startswith(f'{param}=') for param in SENSITIVE_PARAMS):
            param_name = arg.split('=')[0]
            sanitized.append(f'{param_name}=[REDACTED]')
            continue

        # Check for --key value format
        if arg in SENSITIVE_PARAMS:
            sanitized.append(arg)
            skip_next = True
            continue

        sanitized.append(arg)

    return sanitized

# Usage:
if debug:
    safe_cmd = sanitize_command_for_logging(cmd)
    print(f'[DEBUG] Crypto: Running: {" ".join(safe_cmd)}', file=sys.stderr)
```

Also sanitize cryptographic values:
```python
if debug:
    print(f'[DEBUG] shared_secret length = {len(shared_secret)}', file=sys.stderr)
    # ❌ DON'T: print(f'[DEBUG] shared_secret (hex) = {shared_secret.hex()}')
    print(f'[DEBUG] shared_secret (hex) = [REDACTED]', file=sys.stderr)
```

#### 2. **Secrets in Process Arguments** (MEDIUM severity)
**Location:** src/yb/piv.py:329-330

```python
if management_key:
    cmd += [f'--key={management_key}']
```

**Issue:** Command-line arguments are visible in process listings (`ps aux`, `/proc/*/cmdline`)

**Recommendation:** Use one of these methods:

**Option 1: Environment variables**
```python
env = os.environ.copy()
if management_key:
    env['YKPIV_KEY'] = management_key

subprocess.run(cmd, env=env, ...)
```

**Option 2: Stdin (if tool supports)**
```python
if management_key:
    subprocess.run(
        cmd,
        input=f"key:{management_key}\n".encode(),
        ...
    )
```

**Option 3: Temporary file with secure permissions**
```python
import tempfile
import os

if management_key:
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        os.chmod(f.name, 0o600)  # Owner read/write only
        f.write(management_key)
        key_file = f.name

    try:
        cmd += ['--key-file', key_file]
        subprocess.run(cmd, ...)
    finally:
        os.unlink(key_file)
```

#### 3. **No Memory Zeroing** (LOW severity)

**Issue:** Sensitive data (PINs, keys, plaintexts) remains in Python memory after use. Python doesn't provide memory zeroing mechanisms.

**Impact:**
- Core dumps may contain secrets
- Memory analysis tools can extract secrets
- Secrets persist until garbage collection

**Partial Mitigation (limited effectiveness in Python):**
```python
def secure_zero(data: bytearray):
    """Attempt to zero sensitive data (limited in Python)."""
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0

# Usage:
sensitive_data = bytearray(b'secret')
try:
    # Use sensitive_data
    pass
finally:
    secure_zero(sensitive_data)
    del sensitive_data
```

**Note:** Python's memory management makes true secure zeroing difficult. Consider:
- Warning users about memory dumps
- Disabling core dumps on sensitive systems
- Using short-lived processes

#### 4. **getpass Usage Without Timeout** (LOW severity)
**Location:** src/yb/auxiliaries.py:468-470

```python
import getpass
print('PIN required for PIN-protected management key mode...', file=sys.stderr)
pin = getpass.getpass('Enter PIN: ')
```

**Issue:** No timeout on PIN entry. Terminal could be left in "waiting for input" state indefinitely.

**Recommendation:**
```python
import getpass
import signal

class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("PIN entry timeout")

def secure_getpass(prompt: str, timeout: int = 60) -> str:
    """Get password with timeout."""
    # Set alarm for timeout
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

    try:
        password = getpass.getpass(prompt)
        signal.alarm(0)  # Cancel alarm
        return password
    except TimeoutError:
        print("\nPIN entry timeout", file=sys.stderr)
        raise
```

---

## 7. Build and Deployment Security

### ⚠️ **Issues**

#### 1. **No Signed Releases** (MEDIUM severity)

**Issue:** No GPG-signed releases or checksums provided. Users cannot verify authenticity.

**Recommendation:**

```bash
# Sign release tags
git tag -s v0.1.0 -m "Release v0.1.0"

# Generate checksums
sha256sum yb-0.1.0.tar.gz > yb-0.1.0.tar.gz.sha256
gpg --detach-sign --armor yb-0.1.0.tar.gz.sha256

# Include in release notes
```

#### 2. **No CI/CD Security Checks** (MEDIUM severity)

**Missing:**
- Automated security scanning
- Dependency vulnerability checking
- SAST (Static Application Security Testing)
- Secret scanning

**Recommendation:** See section 5.3 for GitHub Actions workflow

#### 3. **Missing Security Policy** (LOW severity)

**Recommendation:** Create `SECURITY.md`:

```markdown
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**DO NOT** open public issues for security vulnerabilities.

Instead, please email: fred@atlant.is

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within 48 hours and provide a timeline for fixes.

## Security Considerations

yb handles sensitive cryptographic material. Users should:
- Change default YubiKey credentials
- Use PIN-protected management key mode
- Keep YubiKey firmware updated
- Protect physical access to YubiKey
- Avoid using --debug flag with sensitive operations
```

---

## 8. Additional Security Concerns

### 1. **Time-of-Check to Time-of-Use (TOCTOU)** (LOW severity)

**Location:** Multiple locations where device enumeration happens before operations

**Issue:** Device list could change between enumeration and operation.

**Recommendation:** Add device verification after selection:
```python
def verify_device_still_present(reader: str, piv: PivInterface) -> bool:
    """Verify selected device is still connected."""
    current_devices = piv.list_devices()
    return any(r == reader for _, _, r in current_devices)
```

### 2. **No Audit Logging** (MEDIUM severity)

**Issue:** No logging of security-relevant events:
- PIN verification attempts
- Management key usage
- Blob creation/deletion
- Encryption operations

**Recommendation:**
```python
import logging
import syslog

security_logger = logging.getLogger('yb.security')
security_logger.setLevel(logging.INFO)

# Log to syslog for audit trail
handler = logging.handlers.SysLogHandler(address='/dev/log')
security_logger.addHandler(handler)

# Usage:
security_logger.info(f"PIN verification attempted for reader {reader}")
security_logger.info(f"Blob created: {name} (encrypted={encrypted})")
```

### 3. **Error Messages Leak Information** (LOW severity)

**Example:** src/yb/store.py:102-104
```python
raise click.ClickException(
    f'Store has bad yblob magic: {yblob_magic:08x}')
```

**Issue:** Detailed error messages could help attackers understand internal state.

**Recommendation:** Provide detailed errors only in debug mode:
```python
if debug:
    raise click.ClickException(
        f'Store has bad yblob magic: {yblob_magic:08x}')
else:
    raise click.ClickException(
        'Store corruption detected. Use --debug for details.')
```

---

## 9. Recommendations by Priority

### 🔴 CRITICAL (Fix Immediately)

1. **Add authenticated encryption (AES-GCM)** instead of AES-CBC
   - Prevents ciphertext manipulation attacks
   - Industry best practice for security
   - Location: src/yb/crypto.py:260-410

2. **Sanitize debug output** to prevent secrets leakage
   - Redact management keys, PINs, cryptographic material
   - Location: src/yb/crypto.py (all debug prints)

### 🟠 HIGH (Fix Soon)

3. **Pin dependency versions** to prevent supply chain attacks
   - Add version constraints in pyproject.toml
   - Create requirements-lock.txt

4. **Validate reader names** to prevent potential injection
   - Add validation before subprocess calls
   - Location: src/yb/main.py:204-217

5. **Move secrets out of process arguments**
   - Use environment variables or temp files
   - Location: src/yb/piv.py:329-330

### 🟡 MEDIUM (Address in Next Release)

6. **Add dependency vulnerability scanning** to CI/CD
   - Integrate safety, pip-audit, bandit

7. **Validate X.509 subject strings**
   - Prevent special character issues
   - Location: src/yb/crypto.py:47-48

8. **Implement audit logging** for security events

9. **Add signed releases** and checksums

10. **Create SECURITY.md** file

### 🟢 LOW (Consider for Future)

11. **Add key rotation mechanism**

12. **Normalize Unicode in blob names**

13. **Add timeout to PIN entry**

14. **Reduce error message verbosity**

---

## 10. Compliance Considerations

### NIST Guidelines

- ✅ NIST SP 800-73 (PIV card interface) - Compliant
- ⚠️ NIST SP 800-38D (GCM mode) - Should use GCM instead of CBC
- ✅ NIST SP 800-56A (Key agreement) - ECDH properly implemented

### Common Criteria

- ⚠️ Missing audit trail (FPT_STM)
- ⚠️ Lack of integrity protection (FDP_ITC)

### PCI DSS (if handling payment data)

- ⚠️ Requirement 3.4 (Render PAN unreadable) - Use AEAD
- ⚠️ Requirement 10 (Track access) - Add audit logging

---

## 11. Testing Recommendations

### Security Test Cases Needed

1. **Fuzzing Input Validation**
   ```python
   # Fuzz blob names
   fuzz_inputs = [
       '\x00' * 256,  # Null bytes
       'A' * 1000,    # Length overflow
       '../../../../etc/passwd',  # Path traversal
       '$(whoami)',   # Command injection
       '<script>',    # XSS-like
   ]
   ```

2. **Ciphertext Manipulation Tests**
   ```python
   # Verify integrity protection
   encrypted_blob = store_blob(...)
   # Flip bits in ciphertext
   modified_blob = flip_random_bit(encrypted_blob)
   # Should fail with clear error
   with pytest.raises(IntegrityError):
       fetch_blob(modified_blob)
   ```

3. **Race Condition Tests**
   ```python
   # Test TOCTOU vulnerabilities
   # Simulate device removal during operation
   ```

4. **Secret Leakage Tests**
   ```python
   # Capture all output and verify no secrets present
   output = capture_subprocess_output(yb_command)
   assert management_key not in output
   assert pin not in output
   ```

---

## 12. Conclusion

The **yb** YubiKey blob storage tool demonstrates **good security practices** in several areas, particularly:

- Proactive default credential detection
- Proper use of cryptographic libraries
- PIN-protected management key support
- Hardware-backed security with YubiKey

However, there are **critical issues** that should be addressed:

1. **Lack of authenticated encryption** (use AES-GCM)
2. **Secrets exposure in debug output**
3. **No dependency version pinning**
4. **Potential command injection vectors**

### Overall Risk Assessment

**Current Risk Level:** MEDIUM-HIGH

**Risk After Fixes:** LOW

The tool is suitable for personal use by security-conscious users who understand the limitations. For enterprise deployment or handling highly sensitive data, the critical issues must be addressed first.

---

## 13. Contact

For questions about this security analysis:
- **Analysis conducted by:** Claude (Anthropic AI Assistant)
- **Analysis date:** 2025-12-02
- **Project maintainer:** fred@atlant.is

---

## Appendix: Security Checklist

- [x] Authentication mechanisms reviewed
- [x] Input validation analyzed
- [x] Cryptographic implementation examined
- [x] Command injection vectors identified
- [x] Dependency security assessed
- [x] Secrets management evaluated
- [x] Build/deployment security reviewed
- [ ] Penetration testing conducted (recommended)
- [ ] Third-party security audit (recommended for production)
- [ ] Cryptographic implementation audit by specialist (recommended)

---

**End of Security Analysis Report**
