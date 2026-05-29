"""
InnoDB Page Scanner for MySQL 8.0
Scans raw InnoDB files (.ibd, ibdata1) for valid pages
"""

import os
import struct
import logging
from typing import List, Optional, Iterator, Tuple
from dataclasses import dataclass, field

from utils.config import (
    UNIV_PAGE_SIZE, VALID_PAGE_SIZES,
    FIL_PAGE_TYPE, FIL_PAGE_OFFSET,
    FIL_PAGE_INDEX, FIL_PAGE_SDI, FIL_PAGE_RTREE,
    INDEX_PAGE_TYPES, BLOB_PAGE_TYPES, LOB_PAGE_TYPES,
    COMPRESSION_TYPES, ENCRYPTED_TYPES,
    FIL_PAGE_TYPE_BLOB,
    FIL_PAGE_ARCH_LOG_NO_OR_SPACE_ID,
    PAGE_HEADER, PAGE_INDEX_ID, PAGE_LEVEL,
    PAGE_N_HEAP, PAGE_N_RECS,
    PAGE_FREE, PAGE_GARBAGE,
    PAGE_NEW_INFIMUM_OFFSET, INFIMUM_DATA,
    FIL_NULL,
)
from parser.checksum import (
    mach_read_from_2, mach_read_from_4, mach_read_from_8,
    validate_checksum,
)
from parser.page_parser import InnoDBPage, parse_film_header

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Results of scanning an InnoDB file."""
    filename: str = ''
    file_size: int = 0
    total_pages: int = 0
    valid_pages: int = 0
    index_pages: int = 0
    sdi_pages: int = 0
    blob_pages: int = 0
    leaf_pages: int = 0
    pages_with_deleted_recs: int = 0
    index_ids: List[int] = field(default_factory=list)
    pages: List[InnoDBPage] = field(default_factory=list)
    encrypted: bool = False


def detect_page_size(filepath: str) -> int:
    """
    Try to detect the InnoDB page size from a file.
    MySQL 8.0 supports 4KB, 8KB, 16KB, 32KB, 64KB.
    """
    file_size = os.path.getsize(filepath)
    for ps in sorted(VALID_PAGE_SIZES, reverse=True):
        if file_size >= ps and file_size % ps == 0:
            # Verify by checking if first page looks valid
            try:
                with open(filepath, 'rb') as f:
                    f.seek(0)
                    data = f.read(ps)
                    if len(data) == ps:
                        page_type = mach_read_from_2(data, FIL_PAGE_TYPE)
                        page_no = mach_read_from_4(data, FIL_PAGE_OFFSET)
                        if page_no == 0 or page_type in INDEX_PAGE_TYPES:
                            return ps
            except Exception:
                continue
    return UNIV_PAGE_SIZE  # Default to 16KB


def scan_file_for_pages(filepath: str, page_size: int = None,
                        index_id_filter: int = None,
                        checksum_algo: int = None,
                        include_deleted_pages: bool = True) -> ScanResult:
    """
    Scan a raw InnoDB file for valid pages.

    Args:
        filepath: Path to the InnoDB file (.ibd or ibdata1)
        page_size: Page size (auto-detected if None)
        index_id_filter: Only collect pages with this index_id
        checksum_algo: Checksum algorithm to use (None = try all)
        include_deleted_pages: Include pages from free list (may contain deleted records)

    Returns:
        ScanResult with all found pages
    """
    if not os.path.exists(filepath):
        logger.error(f"File not found: {filepath}")
        return ScanResult()

    file_size = os.path.getsize(filepath)
    if page_size is None:
        page_size = detect_page_size(filepath)

    result = ScanResult(
        filename=filepath,
        file_size=file_size,
        total_pages=file_size // page_size,
    )

    logger.info(f"Scanning {filepath} (size={file_size}, page_size={page_size}, pages={result.total_pages})")

    chunk_size = 64 * 1024 * 1024  # Read in 64MB chunks
    index_ids_seen = set()

    try:
        with open(filepath, 'rb') as f:
            file_offset = 0
            while file_offset < file_size:
                read_size = min(chunk_size, file_size - file_offset)
                data = f.read(read_size)
                if not data:
                    break

                # Process pages in the read buffer
                buf_offset = 0
                while buf_offset + page_size <= len(data):
                    page_data = data[buf_offset:buf_offset + page_size]
                    page_no = file_offset + buf_offset

                    page = process_raw_page(page_data, page_no, page_size,
                                            checksum_algo, index_id_filter,
                                            include_deleted_pages)

                    if page is not None:
                        result.valid_pages += 1
                        if page.page_type == FIL_PAGE_INDEX:
                            result.index_pages += 1
                            if page.level == 0:
                                result.leaf_pages += 1
                            if page.index_id not in index_ids_seen:
                                index_ids_seen.add(page.index_id)
                                result.index_ids.append(page.index_id)
                        elif page.page_type == FIL_PAGE_SDI:
                            result.sdi_pages += 1
                        elif page.page_type in BLOB_PAGE_TYPES or page.page_type in LOB_PAGE_TYPES:
                            result.blob_pages += 1

                        # Check for deleted records
                        garbage = mach_read_from_2(page_data, PAGE_HEADER + PAGE_GARBAGE)
                        if garbage > 0:
                            result.pages_with_deleted_recs += 1

                        # Check encryption
                        if page.page_type in ENCRYPTED_TYPES:
                            result.encrypted = True

                        result.pages.append(page)

                    buf_offset += page_size

                file_offset += read_size

                # Progress logging
                progress = (file_offset / file_size) * 100
                if progress % 10 < (page_size / file_size) * 100 + 1:
                    logger.info(f"  Progress: {progress:.1f}%")

    except Exception as e:
        logger.error(f"Error scanning {filepath}: {e}")

    logger.info(f"Scan complete: {result.valid_pages}/{result.total_pages} valid pages, "
                f"{result.index_pages} index pages, {result.leaf_pages} leaf pages, "
                f"{result.sdi_pages} SDI pages, {result.blob_pages} BLOB pages")

    return result


def process_raw_page(page_data: bytes, page_no: int, page_size: int,
                      checksum_algo: int = None,
                      index_id_filter: int = None,
                      include_deleted_pages: bool = True) -> Optional[InnoDBPage]:
    """
    Process a single raw page and return InnoDBPage if valid.
    """
    if len(page_data) < page_size:
        return None

    # Skip empty pages
    if page_data[:4] == b'\x00\x00\x00\x00' and page_data[4:8] == b'\x00\x00\x00\x00':
        # Check if entirely zero
        if all(b == 0 for b in page_data[:page_size]):
            return None

    # Parse FIL header
    fil_header = parse_film_header(page_data)
    page_type = fil_header.get('page_type', 0)
    actual_page_no = fil_header.get('page_no', 0)

    # For index pages, validate more strictly
    if page_type in INDEX_PAGE_TYPES:
        # Check page number matches offset
        if actual_page_no == 0:
            return None

        # Validate checksum
        is_valid, algo = validate_checksum(page_data, checksum_algo)
        if not is_valid:
            # For recovery, we may still want to process pages with bad checksums
            # Log but don't skip
            logger.debug(f"Page {page_no} has invalid checksum")

        # Validate infimum/supremum
        compact = bool(mach_read_from_4(page_data, PAGE_HEADER + PAGE_N_HEAP) & 0x80000000)
        inf_offset = 99 if compact else 101  # PAGE_NEW_INFIMUM_OFFSET / PAGE_OLD_INFIMUM_OFFSET

        if inf_offset + 8 <= page_size:
            infimum = page_data[inf_offset:inf_offset + 8]
            if infimum != INFIMUM_DATA:
                # Not a valid index page, skip
                return None

        # Filter by index_id if specified
        if index_id_filter is not None:
            idx_id = mach_read_from_8(page_data, PAGE_HEADER + PAGE_INDEX_ID)
            if idx_id != index_id_filter:
                return None

        # Check for deleted records only mode
        if not include_deleted_pages:
            garbage = mach_read_from_2(page_data, PAGE_HEADER + PAGE_GARBAGE)
            n_recs = mach_read_from_2(page_data, PAGE_HEADER + PAGE_N_RECS)
            free = mach_read_from_2(page_data, PAGE_HEADER + PAGE_FREE)
            if garbage == 0 and (n_recs == 0 or free == 0):
                return None

        return InnoDBPage(
            page_type=page_type,
            page_no=actual_page_no,
            space_id=fil_header.get('space_id', 0),
            lsn=fil_header.get('lsn', 0),
            prev_page=fil_header.get('prev_page', 0),
            next_page=fil_header.get('next_page', 0),
            level=mach_read_from_2(page_data, PAGE_HEADER + PAGE_LEVEL),
            index_id=mach_read_from_8(page_data, PAGE_HEADER + PAGE_INDEX_ID),
            n_recs=mach_read_from_2(page_data, PAGE_HEADER + PAGE_N_RECS),
            n_heap=mach_read_from_4(page_data, PAGE_HEADER + PAGE_N_HEAP) & 0x3FFFFFFF,
            heap_top=mach_read_from_2(page_data, PAGE_HEADER + 24),  # PAGE_HEAP_TOP
            free_offset=mach_read_from_2(page_data, PAGE_HEADER + PAGE_FREE),
            garbage_bytes=mach_read_from_2(page_data, PAGE_HEADER + PAGE_GARBAGE),
            is_compact=compact,
            checksum_algo=algo or 0,
            raw_data=page_data,
        )

    elif page_type == FIL_PAGE_TYPE_BLOB or page_type in BLOB_PAGE_TYPES:
        # BLOB pages are also useful for recovery
        return InnoDBPage(
            page_type=page_type,
            page_no=actual_page_no,
            space_id=fil_header.get('space_id', 0),
            raw_data=page_data,
        )

    return None


def scan_all_ibd_files(datadir: str, database: str = None,
                       table: str = None) -> List[ScanResult]:
    """
    Scan all .ibd files in the data directory.
    If database is specified, only scan that database's files.
    If table is also specified, only scan that table's .ibd file.
    """
    results = []

    if database and table:
        # Scan specific table
        ibd_path = os.path.join(datadir, database, f'{table}.ibd')
        if os.path.exists(ibd_path):
            result = scan_file_for_pages(ibd_path)
            results.append(result)
    elif database:
        # Scan all tables in database
        db_dir = os.path.join(datadir, database)
        if os.path.isdir(db_dir):
            for fname in os.listdir(db_dir):
                if fname.endswith('.ibd'):
                    ibd_path = os.path.join(db_dir, fname)
                    result = scan_file_for_pages(ibd_path)
                    results.append(result)
    else:
        # Scan entire datadir recursively
        for root, dirs, files in os.walk(datadir):
            for fname in files:
                if fname.endswith('.ibd'):
                    ibd_path = os.path.join(root, fname)
                    result = scan_file_for_pages(ibd_path)
                    results.append(result)
        # Also scan ibdata1
        ibdata_path = os.path.join(datadir, 'ibdata1')
        if os.path.exists(ibdata_path):
            result = scan_file_for_pages(ibdata_path)
            results.append(result)

    return results
