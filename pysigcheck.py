#!/usr/bin/env python3
"""pysigcheck - A Python implementation of Sysinternals sigcheck -h functionality."""

import argparse
import ctypes
import hashlib
import os
import sys
from datetime import datetime

import pefile
from signify.authenticode import CertificateTrustList
from signify.authenticode.signed_file import SignedPEFile
from signify.authenticode.verification_result import AuthenticodeVerificationResult


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


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_byte * 8),
    ]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_uint32),
        ("pcwszFilePath", ctypes.c_wchar_p),
        ("hFile", ctypes.c_void_p),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_uint32),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", ctypes.c_uint32),
        ("fdwRevocationChecks", ctypes.c_uint32),
        ("dwUnionChoice", ctypes.c_uint32),
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction", ctypes.c_uint32),
        ("hWVTStateData", ctypes.c_void_p),
        ("pwszURLReference", ctypes.c_wchar_p),
        ("dwProvFlags", ctypes.c_uint32),
        ("dwUIContext", ctypes.c_uint32),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


# WINTRUST_ACTION_GENERIC_VERIFY_V2
_WVT_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_byte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)

class _WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_uint32),
        ("dwCatalogVersion", ctypes.c_uint32),
        ("pcwszCatalogFilePath", ctypes.c_wchar_p),
        ("pcwszMemberTag", ctypes.c_wchar_p),
        ("pcwszMemberFilePath", ctypes.c_wchar_p),
        ("hMemberFile", ctypes.c_void_p),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", ctypes.c_uint32),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", ctypes.c_void_p),
    ]


class _CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", ctypes.c_uint32), ("wszCatalogFile", ctypes.c_wchar * 260)]


_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_CHOICE_CATALOG = 2
_WTD_STATEACTION_IGNORE = 0
_WTD_SAFER_FLAG = 0x100
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000

_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 1
_OPEN_EXISTING = 3
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


def _load_wintrust():
    """Load wintrust.dll, or return None when not running on Windows."""
    if sys.platform != "win32":
        return None
    try:
        return ctypes.WinDLL("wintrust")
    except (OSError, AttributeError):
        return None


def _win_verify_trust_call(wintrust, data):
    """Invoke WinVerifyTrust with a prepared WINTRUST_DATA. Returns the HRESULT."""
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    wintrust.WinVerifyTrust.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_GUID),
        ctypes.c_void_p,
    ]
    return wintrust.WinVerifyTrust(
        None, ctypes.byref(_WVT_ACTION_GENERIC_VERIFY_V2), ctypes.byref(data)
    )


def _verify_embedded(wintrust, filepath):
    """Verify an embedded Authenticode signature. Returns the HRESULT."""
    file_info = _WINTRUST_FILE_INFO(
        ctypes.sizeof(_WINTRUST_FILE_INFO), filepath, None, None
    )
    data = _WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    data.dwUIChoice = _WTD_UI_NONE
    data.fdwRevocationChecks = _WTD_REVOKE_NONE
    data.dwUnionChoice = _WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = _WTD_STATEACTION_IGNORE
    data.dwProvFlags = _WTD_SAFER_FLAG | _WTD_CACHE_ONLY_URL_RETRIEVAL
    return _win_verify_trust_call(wintrust, data)


def _find_catalog(wintrust, filepath):
    """Look for a security catalog containing this file.

    Returns (catalog_path, member_tag) or (None, None). Tries SHA-256 hashing
    first (CryptCATAdminAcquireContext2, Windows 8+) and falls back to the
    legacy SHA-1 based API.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.CreateFileW(
        ctypes.c_wchar_p(filepath),
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        0,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE or handle is None:
        return None, None

    cat_admin = ctypes.c_void_p()
    try:
        for algorithm in ("SHA256", None):
            if algorithm is not None:
                if not hasattr(wintrust, "CryptCATAdminAcquireContext2"):
                    continue
                acquired = wintrust.CryptCATAdminAcquireContext2(
                    ctypes.byref(cat_admin), None, ctypes.c_wchar_p(algorithm), None, 0
                )
            else:
                acquired = wintrust.CryptCATAdminAcquireContext(
                    ctypes.byref(cat_admin), None, 0
                )
            if not acquired:
                continue

            try:
                hash_size = ctypes.c_uint32(0)
                if algorithm is not None:
                    wintrust.CryptCATAdminCalcHashFromFileHandle2(
                        cat_admin, handle, ctypes.byref(hash_size), None, 0
                    )
                else:
                    wintrust.CryptCATAdminCalcHashFromFileHandle(
                        handle, ctypes.byref(hash_size), None, 0
                    )
                if not hash_size.value:
                    continue

                buf = (ctypes.c_ubyte * hash_size.value)()
                if algorithm is not None:
                    ok = wintrust.CryptCATAdminCalcHashFromFileHandle2(
                        cat_admin, handle, ctypes.byref(hash_size), buf, 0
                    )
                else:
                    ok = wintrust.CryptCATAdminCalcHashFromFileHandle(
                        handle, ctypes.byref(hash_size), buf, 0
                    )
                if not ok:
                    continue

                wintrust.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
                cat_info = wintrust.CryptCATAdminEnumCatalogFromHash(
                    cat_admin, buf, hash_size, 0, None
                )
                if not cat_info:
                    continue

                try:
                    info = _CATALOG_INFO()
                    info.cbStruct = ctypes.sizeof(_CATALOG_INFO)
                    if not wintrust.CryptCATCatalogInfoFromContext(
                        ctypes.c_void_p(cat_info), ctypes.byref(info), 0
                    ):
                        continue
                    member_tag = "".join(f"{b:02X}" for b in buf)
                    return info.wszCatalogFile, member_tag
                finally:
                    wintrust.CryptCATAdminReleaseCatalogContext(
                        cat_admin, ctypes.c_void_p(cat_info), 0
                    )
            finally:
                wintrust.CryptCATAdminReleaseContext(cat_admin, 0)
                cat_admin = ctypes.c_void_p()
        return None, None
    finally:
        kernel32.CloseHandle(handle)


def _verify_catalog(wintrust, filepath, catalog_path, member_tag):
    """Verify a file as a member of a security catalog. Returns the HRESULT."""
    cat_info = _WINTRUST_CATALOG_INFO()
    cat_info.cbStruct = ctypes.sizeof(_WINTRUST_CATALOG_INFO)
    cat_info.pcwszCatalogFilePath = catalog_path
    cat_info.pcwszMemberTag = member_tag
    cat_info.pcwszMemberFilePath = filepath

    data = _WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    data.dwUIChoice = _WTD_UI_NONE
    data.fdwRevocationChecks = _WTD_REVOKE_NONE
    data.dwUnionChoice = _WTD_CHOICE_CATALOG
    data.pFile = ctypes.cast(
        ctypes.pointer(cat_info), ctypes.POINTER(_WINTRUST_FILE_INFO)
    )
    data.dwStateAction = _WTD_STATEACTION_IGNORE
    data.dwProvFlags = _WTD_SAFER_FLAG | _WTD_CACHE_ONLY_URL_RETRIEVAL
    # Keep cat_info alive for the duration of the call.
    status = _win_verify_trust_call(wintrust, data)
    del cat_info
    return status


def win_verify_trust(filepath, allow_catalog=True):
    """Verify a file's signature using the Windows trust provider.

    This is what sigcheck itself uses, so it matches Windows' chain building and
    trust policy exactly. Falls back to catalog verification when the file has no
    embedded signature, which is how most Windows system binaries are signed.

    Returns a dict with 'signed' (bool) and 'catalog' (path or None), or None
    when WinVerifyTrust is not available (i.e. not running on Windows).
    """
    wintrust = _load_wintrust()
    if wintrust is None:
        return None

    filepath = os.path.abspath(filepath)

    if _has_embedded_signature(filepath):
        return {"signed": _verify_embedded(wintrust, filepath) == 0, "catalog": None}

    if not allow_catalog:
        return {"signed": False, "catalog": None}

    try:
        catalog_path, member_tag = _find_catalog(wintrust, filepath)
    except (OSError, AttributeError):
        catalog_path, member_tag = None, None

    if not catalog_path:
        return {"signed": False, "catalog": None}

    signed = _verify_catalog(wintrust, filepath, catalog_path, member_tag) == 0
    return {"signed": signed, "catalog": catalog_path if signed else None}


def _cert_common_name(cert):
    """Return the CN of a certificate's subject, falling back to O, then the full DN."""
    try:
        for attr in ("CN", "O"):
            for value in cert.subject.get_components(attr):
                if value:
                    return value
        return cert.subject.dn or None
    except Exception:
        return None


def _signer_details(signature):
    """Pull (signing_date, publisher) out of a parsed signature."""
    signing_date = None
    publisher = None
    signer = signature.signer_info

    if signer is not None and getattr(signer, "countersigner", None):
        try:
            signing_date = signer.countersigner.signing_time
        except Exception:
            pass

    if signer is not None and signature.certificates:
        for cert in signature.certificates:
            if cert.serial_number == signer.serial_number:
                publisher = _cert_common_name(cert)
                break

    return signing_date, publisher


def _catalog_signer_details(catalog_path):
    """Parse a .cat file to recover its signer name and timestamp.

    A catalog is a PKCS#7 SignedData whose content is a microsoft_ctl, which is
    exactly what signify's CertificateTrustList parses.
    """
    try:
        with open(catalog_path, "rb") as f:
            return _signer_details(CertificateTrustList.from_envelope(f.read()))
    except Exception:
        return None, None


def get_signature_info(filepath):
    """Extract Authenticode signature info from a PE file.

    Returns dict with 'signed' (bool), 'signing_date', 'publisher', 'catalog'.
    """
    result = {
        "signed": False,
        "signing_date": None,
        "publisher": None,
        "catalog": None,
    }

    # Ask Windows for the verdict, so we agree with sigcheck. signify's bundled
    # trust store is stricter than Windows' (e.g. it will not build the longer
    # chain through a cross-signed root to satisfy the timestamping EKU) and it
    # cannot see catalog signatures at all, so it is only a fallback off-Windows.
    verdict = win_verify_trust(filepath)
    if verdict is not None:
        result["signed"] = verdict["signed"]
        result["catalog"] = verdict["catalog"]

    if result["catalog"]:
        # Catalog-signed: the signer lives in the .cat, not in the file.
        result["signing_date"], result["publisher"] = _catalog_signer_details(
            result["catalog"]
        )
        return result

    if not _has_embedded_signature(filepath):
        return result

    try:
        with open(filepath, "rb") as f:
            signed_pe = SignedPEFile(f)
            if verdict is None:
                status, err = signed_pe.explain_verify()
                result["signed"] = status == AuthenticodeVerificationResult.OK

            for sig in signed_pe.iter_embedded_signatures():
                result["signing_date"], result["publisher"] = _signer_details(sig)
                break  # Only need the first signature
    except Exception:
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


def format_link_date(filepath):
    """Get PE link date (TimeDateStamp from COFF header) formatted like sigcheck."""
    try:
        pe = pefile.PE(filepath, fast_load=True)
        timestamp = pe.FILE_HEADER.TimeDateStamp
        pe.close()
        dt = datetime.fromtimestamp(timestamp)
        hour = dt.hour % 12
        if hour == 0:
            hour = 12
        ampm = "AM" if dt.hour < 12 else "PM"
        return f"{hour}:{dt.minute:02d} {ampm} {dt.month}/{dt.day}/{dt.year}"
    except Exception:
        return "n/a"


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
        lines.append(f"{file_size} (0x{file_size:X})  bytes")

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
            link_date = format_link_date(filepath)
            lines.append(f"\tLink date:\t{link_date}")

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
    # Certificate subjects and version strings are arbitrary Unicode; the Windows
    # console default (cp1252) cannot encode e.g. CJK publisher names and would
    # otherwise abort the whole run with UnicodeEncodeError.
    try:
        sys.stdout.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass

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
