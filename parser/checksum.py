"""
MySQL 8.0 InnoDB Checksum Algorithms
Supports: crc32, strict_crc32, strict_innodb, innodb, none
Based on MySQL 8.0 source: storage/innobase/include/buf0checksum.h
"""

import struct
import zlib

from utils.config import (
    UNIV_PAGE_SIZE,
    FIL_PAGE_SPACE_OR_CHKSUM,
    FIL_PAGE_OFFSET,
    FIL_PAGE_FILE_FLUSH_LSN,
    FIL_PAGE_DATA,
    FIL_PAGE_END_LSN_OLD_CHKSUM,
    FIL_PAGE_DATA_END,
    UT_HASH_RANDOM_MASK,
    UT_HASH_RANDOM_MASK2,
)


def ut_fold_ulint_pair(n1: int, n2: int) -> int:
    """Fold two ulint values into one hash value."""
    return ((((n1 ^ n2 ^ UT_HASH_RANDOM_MASK2) << 8) + n1)
            ^ UT_HASH_RANDOM_MASK) + n2


def ut_fold_binary(data: bytes) -> int:
    """Calculate a fold hash over binary data."""
    fold = 0
    for b in data:
        fold = ut_fold_ulint_pair(fold, b)
    return fold


def mach_read_from_4(data: bytes, offset: int = 0) -> int:
    """Read a 4-byte big-endian unsigned integer."""
    if offset + 4 > len(data):
        return 0
    return struct.unpack('>I', data[offset:offset + 4])[0]


def mach_read_from_2(data: bytes, offset: int = 0) -> int:
    """Read a 2-byte big-endian unsigned integer."""
    if offset + 2 > len(data):
        return 0
    return struct.unpack('>H', data[offset:offset + 2])[0]


def mach_read_from_8(data: bytes, offset: int = 0) -> int:
    """Read an 8-byte big-endian unsigned integer."""
    if offset + 8 > len(data):
        return 0
    return struct.unpack('>Q', data[offset:offset + 8])[0]


def buf_calc_page_old_checksum(page: bytes) -> int:
    """
    Calculate old-style InnoDB checksum.
    NOTE: FIL_PAGE_SPACE_OR_CHKSUM must contain the new checksum value
    before calling this, as the old checksum includes those bytes.
    """
    # Old checksum only looks at first FIL_PAGE_FILE_FLUSH_LSN bytes
    checksum = ut_fold_binary(page[:FIL_PAGE_FILE_FLUSH_LSN])
    return checksum & 0xFFFFFFFF


def buf_calc_page_new_checksum(page: bytes) -> int:
    """
    Calculate new-style InnoDB checksum.
    Skips FIL_PAGE_SPACE_OR_CHKSUM, FIL_PAGE_FILE_FLUSH_LSN fields,
    and last 8 bytes (old checksum + LSN).
    """
    checksum = (ut_fold_binary(page[FIL_PAGE_OFFSET:FIL_PAGE_FILE_FLUSH_LSN])
                 + ut_fold_binary(page[FIL_PAGE_DATA:
                                     UNIV_PAGE_SIZE - FIL_PAGE_DATA_END]))
    return checksum & 0xFFFFFFFF


def buf_calc_page_crc32(page: bytes, use_legacy_big_endian: bool = False) -> int:
    """
    Calculate CRC32 checksum of a page.
    Skips FIL_PAGE_SPACE_OR_CHKSUM field and last 8 bytes.
    """
    # Build the buffer for CRC calculation:
    # bytes 4..FIL_PAGE_FILE_FLUSH_LSN + bytes FIL_PAGE_DATA..end-8
    buf = bytearray()
    buf.extend(page[FIL_PAGE_OFFSET:FIL_PAGE_FILE_FLUSH_LSN])
    buf.extend(page[FIL_PAGE_DATA:UNIV_PAGE_SIZE - FIL_PAGE_DATA_END])

    if use_legacy_big_endian:
        # Legacy big endian: swap byte order within each 4-byte word
        swapped = bytearray()
        for i in range(0, len(buf), 4):
            chunk = buf[i:i + 4]
            if len(chunk) == 4:
                swapped.extend(chunk[::-1])
            else:
                swapped.extend(chunk)
        buf = swapped

    return zlib.crc32(bytes(buf)) & 0xFFFFFFFF


def validate_checksum(page: bytes, algorithm: int = None) -> bool:
    """
    Validate page checksum using the specified algorithm.
    If algorithm is None, tries all algorithms.

    Returns (is_valid, algorithm_used_or_none)
    """
    if len(page) != UNIV_PAGE_SIZE:
        return False, None

    # Read stored checksums from page
    checksum_field1 = mach_read_from_4(page, FIL_PAGE_SPACE_OR_CHKSUM)  # new checksum
    checksum_field2 = mach_read_from_4(page, UNIV_PAGE_SIZE - FIL_PAGE_END_LSN_OLD_CHKSUM)  # old checksum

    if checksum_field1 == 0 and checksum_field2 == 0:
        return False, None

    if algorithm is not None:
        return _check_single_algorithm(page, checksum_field1, checksum_field2, algorithm)

    # Try all algorithms
    for algo in [4, 3, 2, 1, 0]:  # strict_crc32, crc32, strict_innodb, innodb, none
        valid, _ = _check_single_algorithm(page, checksum_field1, checksum_field2, algo)
        if valid:
            return True, algo

    return False, None


def _check_single_algorithm(page: bytes, field1: int, field2: int, algo: int) -> tuple:
    """Check a single checksum algorithm."""
    try:
        if algo in (0,):  # none
            return True, algo

        elif algo in (1, 2):  # innodb, strict_innodb
            old_calc = buf_calc_page_old_checksum(page)
            if old_calc != field2:
                return False, None

            new_calc = buf_calc_page_new_checksum(page)
            if field1 != 0 and new_calc == field1:
                return True, algo
            # For innodb (non-strict), also accept if stored is 0
            if algo == 1 and field1 == 0:
                return True, algo
            return False, None

        elif algo in (3, 4):  # crc32, strict_crc32
            crc = buf_calc_page_crc32(page, use_legacy_big_endian=False)
            if crc == field1:
                return True, algo
            crc_legacy = buf_calc_page_crc32(page, use_legacy_big_endian=True)
            if crc_legacy == field1:
                return True, algo
            return False, None

    except Exception:
        return False, None

    return False, None
