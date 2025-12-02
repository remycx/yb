#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
#
# SPDX-License-Identifier: MIT

"""
Migration script to re-encrypt blobs with AES-GCM (v2) format.

This script migrates blobs encrypted with the legacy AES-CBC format (v1)
to the new AES-GCM authenticated encryption format (v2).

Usage:
    python scripts/migrate_to_aead.py [options]

Options:
    --serial SERIAL   YubiKey serial number
    --reader READER   PC/SC reader name (legacy)
    --pin PIN         YubiKey PIN (will prompt if not provided)
    --dry-run         Show what would be migrated without making changes
    --backup-dir DIR  Create backup copies in specified directory
    --yes             Skip confirmation prompts
"""

import argparse
import getpass
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from yb.piv import HardwarePiv
from yb.orchestrator import list_blobs, fetch_blob, remove_blob, store_blob


def main():
    parser = argparse.ArgumentParser(
        description='Migrate yb blobs from AES-CBC to AES-GCM encryption'
    )
    parser.add_argument(
        '--serial',
        type=int,
        help='YubiKey serial number'
    )
    parser.add_argument(
        '--reader',
        type=str,
        help='PC/SC reader name (legacy)'
    )
    parser.add_argument(
        '--pin',
        type=str,
        help='YubiKey PIN (will prompt if not provided)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be migrated without making changes'
    )
    parser.add_argument(
        '--backup-dir',
        type=Path,
        help='Create backup copies in specified directory'
    )
    parser.add_argument(
        '--yes',
        action='store_true',
        help='Skip confirmation prompts'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("YB Blob Encryption Migration Tool")
    print("=" * 70)
    print()
    print("This tool will migrate encrypted blobs from AES-CBC (v1)")
    print("to AES-GCM (v2) authenticated encryption format.")
    print()

    # Initialize PIV interface
    piv = HardwarePiv()

    # Select reader
    if args.serial:
        try:
            reader = piv.get_reader_for_serial(args.serial)
            print(f"Using YubiKey {args.serial}")
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
    elif args.reader:
        reader = args.reader
        print(f"Using reader: {reader}")
    else:
        # Auto-select single device
        devices = piv.list_devices()
        if len(devices) == 0:
            print("Error: No YubiKeys found", file=sys.stderr)
            return 1
        elif len(devices) == 1:
            serial, version, reader = devices[0]
            print(f"Auto-selected YubiKey {serial} (version {version})")
        else:
            print("Error: Multiple YubiKeys detected. Use --serial to specify one.")
            for serial, version, _ in devices:
                print(f"  - Serial {serial} (YubiKey {version})")
            return 1

    # Get PIN if not provided
    pin = args.pin
    if not pin:
        pin = getpass.getpass("Enter YubiKey PIN: ")

    # Create backup directory if specified
    if args.backup_dir:
        args.backup_dir.mkdir(parents=True, exist_ok=True)
        print(f"Backups will be saved to: {args.backup_dir}")
        print()

    # List all blobs
    print("Scanning for blobs...")
    try:
        blobs = list_blobs(reader, piv)
    except Exception as e:
        print(f"Error listing blobs: {e}", file=sys.stderr)
        return 1

    if not blobs:
        print("No blobs found.")
        return 0

    # Filter encrypted blobs
    encrypted_blobs = [
        (name, size, is_enc, mtime, chunks)
        for name, size, is_enc, mtime, chunks in blobs
        if is_enc
    ]

    if not encrypted_blobs:
        print("No encrypted blobs found. Nothing to migrate.")
        return 0

    print(f"\nFound {len(encrypted_blobs)} encrypted blob(s):")
    print()
    print(f"{'Name':<30} {'Size':<10} {'Chunks':<7}")
    print("-" * 50)
    for name, size, _, _, chunks in encrypted_blobs:
        print(f"{name:<30} {size:<10} {chunks:<7}")
    print()

    # Confirm migration
    if not args.yes and not args.dry_run:
        response = input(f"Migrate {len(encrypted_blobs)} blob(s)? [y/N]: ")
        if response.lower() != 'y':
            print("Migration cancelled.")
            return 0

    # Migrate each blob
    success_count = 0
    fail_count = 0

    for name, size, _, mtime, chunks in encrypted_blobs:
        print(f"\nProcessing: {name}")

        if args.dry_run:
            print("  [DRY RUN] Would fetch, backup, delete, and re-store")
            success_count += 1
            continue

        try:
            # Fetch the blob (decrypts with old format)
            print("  Fetching...", end='', flush=True)
            plaintext = fetch_blob(reader, piv, name, pin=pin, debug=False)
            if plaintext is None:
                print(" FAILED (not found)")
                fail_count += 1
                continue
            print(f" OK ({len(plaintext)} bytes)")

            # Create backup if requested
            if args.backup_dir:
                backup_path = args.backup_dir / f"{name}.backup"
                print(f"  Creating backup: {backup_path}", end='', flush=True)
                with open(backup_path, 'wb') as f:
                    f.write(plaintext)
                print(" OK")

            # Delete old blob
            print("  Deleting old blob...", end='', flush=True)
            removed = remove_blob(reader, piv, name, management_key=None, pin=pin)
            if not removed:
                print(" FAILED (not found)")
                fail_count += 1
                continue
            print(" OK")

            # Re-store with new encryption (will use AES-GCM)
            print("  Storing with AES-GCM...", end='', flush=True)
            stored = store_blob(
                reader=reader,
                piv=piv,
                name=name,
                payload=plaintext,
                encrypted=True,
                management_key=None,
                pin=pin
            )
            if not stored:
                print(" FAILED (store full)")
                fail_count += 1
                # Try to restore from backup if available
                if args.backup_dir:
                    print("  Attempting to restore from backup...")
                    backup_path = args.backup_dir / f"{name}.backup"
                    if backup_path.exists():
                        with open(backup_path, 'rb') as f:
                            backup_data = f.read()
                        store_blob(reader, piv, name, backup_data, True, None, pin)
                        print("  Restored from backup")
                continue
            print(" OK")

            success_count += 1
            print(f"  ✓ Migrated successfully")

        except Exception as e:
            print(f" FAILED: {e}")
            fail_count += 1

    # Summary
    print()
    print("=" * 70)
    print("Migration Summary")
    print("=" * 70)
    if args.dry_run:
        print(f"DRY RUN: Would migrate {success_count} blob(s)")
    else:
        print(f"Successfully migrated: {success_count}")
        print(f"Failed: {fail_count}")

    if args.backup_dir and not args.dry_run:
        print(f"\nBackups saved to: {args.backup_dir}")
        print("You can safely delete backups after verifying the migration.")

    return 0 if fail_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
