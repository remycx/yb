# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
AEAD (Authenticated Encryption with Associated Data) cryptographic operations.

This module provides authenticated encryption using AES-GCM, replacing the
legacy AES-CBC mode which lacks integrity protection.

Security improvements over crypto.py:
- Uses AES-GCM (AEAD) instead of AES-CBC
- Provides integrity and authenticity guarantees
- Protects against ciphertext manipulation attacks
- Protects against padding oracle attacks
- Includes version byte for future algorithm migration
"""

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Encryption format version for future compatibility
CRYPTO_VERSION_AEAD_GCM = 0x02  # Version 2: AES-GCM with AEAD


class CryptoAEAD:
    """
    Authenticated encryption using hybrid ECDH + AES-GCM.

    Wire format:
    [version (1)] || [ephemeral_pubkey (65)] || [nonce (12)] || [ciphertext + auth_tag (N + 16)]

    Total overhead: 1 + 65 + 12 + 16 = 94 bytes
    """

    @classmethod
    def hybrid_encrypt(
            cls,
            blob: bytes,
            peer_public_key
        ) -> bytes:
        """
        Encrypt blob using ECDH + AES-GCM authenticated encryption.

        Args:
            blob: Plaintext data to encrypt
            peer_public_key: Recipient's EC P-256 public key

        Returns:
            Encrypted blob with format:
            version (1 byte) || ephemeral_pub (65 bytes) || nonce (12 bytes) || ciphertext+tag

        The ephemeral public key is included in AAD (Additional Authenticated Data)
        to bind it cryptographically to the ciphertext, preventing key substitution.
        """
        # Generate ephemeral private key for ECDH
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_public_key = ephemeral_private_key.public_key()

        # Perform ECDH to get shared secret
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), peer_public_key)

        # Derive AES-256 key from shared secret using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=None,
            info=b'hybrid-encryption-v2',  # Updated context string for v2
            backend=default_backend(),
        ).derive(shared_secret)

        # Serialize ephemeral public key (will be included in AAD)
        ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        # Generate random nonce (96 bits for GCM)
        nonce = os.urandom(12)

        # Create AES-GCM cipher
        aesgcm = AESGCM(derived_key)

        # Encrypt with authentication
        # AAD includes version and ephemeral public key to bind them to ciphertext
        version_byte = bytes([CRYPTO_VERSION_AEAD_GCM])
        aad = version_byte + ephemeral_pub_bytes

        # encrypt() returns ciphertext || authentication_tag (16 bytes)
        ciphertext_with_tag = aesgcm.encrypt(nonce, blob, aad)

        # Return: version || ephemeral_pub || nonce || (ciphertext + tag)
        return version_byte + ephemeral_pub_bytes + nonce + ciphertext_with_tag


    @classmethod
    def hybrid_decrypt(
            cls,
            serial: int,
            slot: str,
            encrypted_blob: bytes,
            pin: str | None = None,
            debug: bool = False,
        ) -> bytes:
        """
        Decrypt blob using ECDH + AES-GCM authenticated decryption.

        Args:
            serial: YubiKey serial number (used to select correct token for ECDH)
            slot: PIV slot containing the private key (e.g., '9e')
            encrypted_blob: Encrypted data with format:
                version || ephemeral_pubkey || nonce || ciphertext+tag
            pin: Optional PIN for PKCS#11 login
            debug: Enable verbose debugging output (secrets will be redacted)

        Returns:
            Decrypted plaintext bytes

        Raises:
            ValueError: If version is unsupported or blob is malformed
            cryptography.exceptions.InvalidTag: If authentication fails (tampering detected)
        """
        from yb.security_utils import SecureDebug

        # Constants
        VERSION_LEN = 1
        PUB_KEY_LEN = 65  # Uncompressed SECP256R1 point
        NONCE_LEN = 12    # GCM standard nonce size
        AUTH_TAG_LEN = 16 # GCM authentication tag size
        MIN_BLOB_LEN = VERSION_LEN + PUB_KEY_LEN + NONCE_LEN + AUTH_TAG_LEN

        if len(encrypted_blob) < MIN_BLOB_LEN:
            raise ValueError(
                f"Encrypted blob too short: {len(encrypted_blob)} bytes "
                f"(minimum {MIN_BLOB_LEN} bytes required)"
            )

        if debug:
            SecureDebug.print(
                f'hybrid_decrypt: encrypted_blob length = {len(encrypted_blob)} bytes'
            )

        # Parse version byte
        version = encrypted_blob[0]
        if version != CRYPTO_VERSION_AEAD_GCM:
            raise ValueError(
                f"Unsupported crypto version: 0x{version:02x} "
                f"(expected 0x{CRYPTO_VERSION_AEAD_GCM:02x}). "
                f"This blob may have been encrypted with an older version of yb."
            )

        # Slice encrypted blob
        offset = VERSION_LEN
        ephemeral_pub = encrypted_blob[offset : offset + PUB_KEY_LEN]
        offset += PUB_KEY_LEN

        nonce = encrypted_blob[offset : offset + NONCE_LEN]
        offset += NONCE_LEN

        ciphertext_with_tag = encrypted_blob[offset:]

        if debug:
            SecureDebug.print(f'ephemeral_pub length = {len(ephemeral_pub)} bytes')
            SecureDebug.print(f'nonce length = {len(nonce)} bytes')
            SecureDebug.print(f'ciphertext+tag length = {len(ciphertext_with_tag)} bytes')
            # Don't print actual values for security

        # Reconstruct ephemeral public key
        if ephemeral_pub[0] != 0x04:
            raise ValueError(
                f"Invalid ephemeral public key format: expected 0x04 prefix, "
                f"got 0x{ephemeral_pub[0]:02x}"
            )

        x = int.from_bytes(ephemeral_pub[1:33], 'big')
        y = int.from_bytes(ephemeral_pub[33:65], 'big')

        CURVE = ec.SECP256R1()
        public_key = ec.EllipticCurvePublicNumbers(x, y, CURVE).public_key(
            default_backend()
        )

        # Encode to SPKI DER for PKCS#11
        der_spki = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        if debug:
            SecureDebug.print(f'der_spki length = {len(der_spki)} bytes')

        # Import perform_ecdh_with_yubikey from original crypto module
        from yb.crypto import Crypto as LegacyCrypto

        # Derive shared secret via YubiKey
        shared_secret = LegacyCrypto.perform_ecdh_with_yubikey(
            serial, slot, der_spki, pin, debug
        )

        if debug:
            SecureDebug.print(f'shared_secret length = {len(shared_secret)} bytes')

        # Derive AES key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'hybrid-encryption-v2',
            backend=default_backend(),
        ).derive(shared_secret)

        if debug:
            SecureDebug.print('derived AES-256 key from shared secret')

        # Decrypt with authentication
        aesgcm = AESGCM(derived_key)

        # AAD must match encryption (version + ephemeral public key)
        version_byte = bytes([CRYPTO_VERSION_AEAD_GCM])
        aad = version_byte + ephemeral_pub

        try:
            # decrypt() verifies authentication tag and returns plaintext
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
        except Exception as e:
            # Don't leak information about the error
            raise ValueError(
                "Decryption failed: authentication verification failed. "
                "The blob may have been corrupted or tampered with."
            ) from e

        if debug:
            SecureDebug.print(f'plaintext length = {len(plaintext)} bytes')

        return plaintext
