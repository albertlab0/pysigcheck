#!/usr/bin/env python3
"""pysigcheck - A Python implementation of Sysinternals sigcheck -h functionality."""

import argparse
import hashlib
import os
import re
import struct
import sys
from datetime import datetime, timezone

import pefile
from signify.authenticode.signed_file import SignedPEFile
from signify.authenticode.verification_result import AuthenticodeVerificationResult
from signify.exceptions import SignedPEParseError


def compute_hashes(filepath):
    """Compute MD5, SHA1, SHA256 of the entire file."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest().upper(), sha1.hexdigest().upper(), sha256.hexdigest().upper()


def compute_pe_hashes(filepath):
    """Compute PE (Authenticode) hashes - excludes the signature data and checksum.

    Returns (PESHA1, PE256) or (None, None) if not a PE.
    """
    try:
        pe = pefile.PE(filepath, fast_load=True)
    except pefile.PEFormatError:
        return None, None

    try:
        data = open(filepath, "rb").read()

        # The Authenticode hash excludes:
        # 1. The checksum field in the optional header
        # 2. The security directory entry in the data directory
        # 3. The security directory content (the signature itself)

        # Find checksum offset
        checksum_offset = pe.OPTIONAL_HEADER.get_file_offset() + 0x40  # 64 bytes into optional header

        # Find security directory entry offset
        # It's the 5th entry (index 4) in the data directory
        security_dir_offset = None
        security_dir_rva = 0
        security_dir_size = 0
        if hasattr(pe, "OPTIONAL_HEADER") and hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
                sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
                security_dir_rva = sec_dir.VirtualAddress
                security_dir_size = sec_dir.Size
                security_dir_offset = sec_dir.get_file_offset()

        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()

        # Hash up to checksum
        sha1_hash.update(data[:checksum_offset])
        sha256_hash.update(data[:checksum_offset])

        # Skip checksum (4 bytes)
        pos = checksum_offset + 4

        if security_dir_offset is not None:
            # Hash from after checksum to security directory entry
            sha1_hash.update(data[pos:security_dir_offset])
            sha256_hash.update(data[pos:security_dir_offset])

            # Skip security directory entry (8 bytes: VirtualAddress + Size)
            pos = security_dir_offset + 8

        # Hash from after security dir entry to the start of the actual signature data
        if security_dir_rva > 0 and security_dir_size > 0:
            # The security data is at the RVA (which is a file offset for the cert table)
            sig_offset = security_dir_rva
            sha1_hash.update(data[pos:sig_offset])
            sha256_hash.update(data[pos:sig_offset])
            # Skip the signature data entirely
        else:
            # No signature, hash the rest
            sha1_hash.update(data[pos:])
            sha256_hash.update(data[pos:])

        pe.close()
        return sha1_hash.hexdigest().upper(), sha256_hash.hexdigest().upper()
    except Exception:
        pe.close()
        return None, None


def compute_imphash(filepath):
    """Compute the import hash of a PE file."""
    try:
        pe = pefile.PE(filepath, fast_load=False)
        imphash = pe.get_imphash()
        pe.close()
        if imphash:
            return imphash.upper()
        return None
    except Exception:
        return None


def get_pe_version_info(filepath):
    """Extract version information from a PE file."""
    info = {
        "company": None,
        "description": None,
        "product": None,
        "prod_version": None,
        "file_version": None,
    }
    try:
        pe = pefile.PE(filepath, fast_load=False)
    except pefile.PEFormatError:
        return info, None

    machine_type = None
    if hasattr(pe, "FILE_HEADER"):
        machine = pe.FILE_HEADER.Machine
        if machine == 0x14C:
            machine_type = "32-bit"
        elif machine == 0x8664:
            machine_type = "64-bit"
        elif machine == 0xAA64:
            machine_type = "ARM64"
        else:
            machine_type = f"0x{machine:X}"

    if hasattr(pe, "VS_VERSIONINFO") or hasattr(pe, "FileInfo"):
        try:
            for file_info in pe.FileInfo:
                for entry in file_info:
                    if hasattr(entry, "StringTable"):
                        for st in entry.StringTable:
                            entries = st.entries
                            info["company"] = entries.get(b"CompanyName", b"").decode(
                                "utf-8", errors="replace"
                            )
                            info["description"] = entries.get(
                                b"FileDescription", b""
                            ).decode("utf-8", errors="replace")
                            info["product"] = entries.get(b"ProductName", b"").decode(
                                "utf-8", errors="replace"
                            )
                            info["prod_version"] = entries.get(
                                b"ProductVersion", b""
                            ).decode("utf-8", errors="replace")
                            info["file_version"] = entries.get(
                                b"FileVersion", b""
                            ).decode("utf-8", errors="replace")
        except (AttributeError, IndexError):
            pass

    pe.close()
    return info, machine_type


def _has_embedded_signature(filepath):
    """Check if a PE has an embedded Authenticode signature by reading the security directory."""
    try:
        pe = pefile.PE(filepath, fast_load=True)
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4:
            sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            has_sig = sec.VirtualAddress != 0 and sec.Size != 0
        else:
            has_sig = False
        pe.close()
        return has_sig
    except Exception:
        return False


def get_signature_info(filepath):
    """Extract Authenticode signature info from a PE file.

    Returns dict with 'signed' (bool), 'signing_date', 'publisher'.
    """
    result = {"signed": False, "signing_date": None, "publisher": None}

    # First check if there's an embedded signature at all
    if not _has_embedded_signature(filepath):
        return result

    try:
        with open(filepath, "rb") as f:
            signed_pe = SignedPEFile(f)
            status, err = signed_pe.explain_verify()
            result["signed"] = (status == AuthenticodeVerificationResult.OK)

            for sig in signed_pe.iter_embedded_signatures():
                signer = sig.signer_info
                # Get signing time from countersigner
                if signer and hasattr(signer, "countersigner") and signer.countersigner:
                    try:
                        result["signing_date"] = signer.countersigner.signing_time
                    except Exception:
                        pass

                # Find the signing certificate by matching serial number
                if signer and sig.certificates:
                    for cert in sig.certificates:
                        if cert.serial_number == signer.serial_number:
                            dn = str(cert.subject)
                            m = re.match(r"CN=([^,]+)", dn)
                            if m:
                                result["publisher"] = m.group(1)
                            break
                break  # Only need the first signature
    except (SignedPEParseError, Exception):
        pass
    return result


def format_datetime(dt):
    """Format datetime like sigcheck: '5:46 PM 4/4/2023'."""
    if dt is None:
        return None
    if hasattr(dt, "timestamp"):
        # Convert to local time
        local_dt = dt.astimezone()
        hour = local_dt.hour % 12
        if hour == 0:
            hour = 12
        ampm = "AM" if local_dt.hour < 12 else "PM"
        return f"{hour}:{local_dt.minute:02d} {ampm} {local_dt.month}/{local_dt.day}/{local_dt.year}"
    return str(dt)


def format_file_date(filepath):
    """Get file modification date formatted like sigcheck."""
    mtime = os.path.getmtime(filepath)
    dt = datetime.fromtimestamp(mtime)
    hour = dt.hour % 12
    if hour == 0:
        hour = 12
    ampm = "AM" if dt.hour < 12 else "PM"
    return f"{hour}:{dt.minute:02d} {ampm} {dt.month}/{dt.day}/{dt.year}"


def is_pe_file(filepath):
    """Check if a file is a PE file by reading the MZ header."""
    try:
        with open(filepath, "rb") as f:
            magic = f.read(2)
            return magic == b"MZ"
    except Exception:
        return False


def sigcheck_h(filepath, show_size=False):
    """Main sigcheck -h implementation."""
    if not os.path.isfile(filepath):
        print(f"Error: File not found: {filepath}")
        return

    lines = []

    # File size info
    if show_size:
        file_size = os.path.getsize(filepath)
        lines.append(f"\t{file_size} (0x{file_size:X})  bytes")

    # Compute file hashes (always)
    md5, sha1, sha256 = compute_hashes(filepath)

    pe = is_pe_file(filepath)

    if pe:
        # Get signature info
        sig_info = get_signature_info(filepath)

        # Get version info
        ver_info, machine_type = get_pe_version_info(filepath)

        # Compute PE hashes
        pesha1, pe256 = compute_pe_hashes(filepath)

        # Compute import hash
        imphash = compute_imphash(filepath)

        # Build output
        if sig_info["signed"]:
            lines.append(f"\tVerified:\tSigned")
            signing_date = format_datetime(sig_info["signing_date"])
            if signing_date:
                lines.append(f"\tSigning date:\t{signing_date}")
        else:
            lines.append(f"\tVerified:\tUnsigned")
            file_date = format_file_date(filepath)
            lines.append(f"\tFile date:\t{file_date}")

        publisher = sig_info["publisher"] if sig_info["signed"] and sig_info["publisher"] else "n/a"
        company = ver_info["company"] if ver_info["company"] else "n/a"
        description = ver_info["description"] if ver_info["description"] else "n/a"
        product = ver_info["product"] if ver_info["product"] else "n/a"
        prod_version = ver_info["prod_version"] if ver_info["prod_version"] else "n/a"
        file_version = ver_info["file_version"] if ver_info["file_version"] else "n/a"
        machine_str = machine_type if machine_type else "n/a"

        lines.append(f"\tPublisher:\t{publisher}")
        lines.append(f"\tCompany:\t{company}")
        lines.append(f"\tDescription:\t{description}")
        lines.append(f"\tProduct:\t{product}")
        lines.append(f"\tProd version:\t{prod_version}")
        lines.append(f"\tFile version:\t{file_version}")
        lines.append(f"\tMachineType:\t{machine_str}")
        lines.append(f"\tMD5:\t{md5}")
        lines.append(f"\tSHA1:\t{sha1}")
        lines.append(f"\tPESHA1:\t{pesha1 if pesha1 else 'n/a'}")
        lines.append(f"\tPE256:\t{pe256 if pe256 else 'n/a'}")
        lines.append(f"\tSHA256:\t{sha256}")
        lines.append(f"\tIMP:\t{imphash if imphash else 'n/a'}")
    else:
        # Non-PE file: only MD5, SHA1, SHA256
        lines.append(f"\tMD5:\t{md5}")
        lines.append(f"\tSHA1:\t{sha1}")
        lines.append(f"\tSHA256:\t{sha256}")

    print("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(
        description="pysigcheck - Python implementation of Sysinternals sigcheck -h"
    )
    parser.add_argument("filepath", help="Path to the file to check")
    parser.add_argument(
        "-s", "--size", action="store_true", help="Display file size information"
    )
    args = parser.parse_args()
    sigcheck_h(args.filepath, show_size=args.size)


if __name__ == "__main__":
    main()
