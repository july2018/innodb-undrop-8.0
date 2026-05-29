"""
InnoDB Page Parser for MySQL 8.0
Parses individual InnoDB pages: header, records, B+tree structure
"""

import struct
import logging
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, field

from utils.config import (
    UNIV_PAGE_SIZE,
    # FIL header
    FIL_PAGE_SPACE_OR_CHKSUM, FIL_PAGE_OFFSET, FIL_PAGE_PREV, FIL_PAGE_NEXT,
    FIL_PAGE_LSN, FIL_PAGE_TYPE, FIL_PAGE_FILE_FLUSH_LSN,
    FIL_PAGE_ARCH_LOG_NO_OR_SPACE_ID, FIL_PAGE_DATA, FIL_PAGE_DATA_END,
    # Page types
    FIL_PAGE_INDEX, FIL_PAGE_SDI, FIL_PAGE_RTREE,
    INDEX_PAGE_TYPES, BLOB_PAGE_TYPES, LOB_PAGE_TYPES,
    COMPRESSION_TYPES, ENCRYPTED_TYPES,
    # Page header
    PAGE_HEADER, PAGE_N_DIR_SLOTS, PAGE_HEAP_TOP, PAGE_N_HEAP,
    PAGE_FREE, PAGE_GARBAGE, PAGE_LAST_INSERT, PAGE_DIRECTION,
    PAGE_N_DIRECTION, PAGE_N_RECS, PAGE_MAX_TRX_ID, PAGE_LEVEL,
    PAGE_INDEX_ID, PAGE_DATA_OFFSET,
    FSEG_HEADER_SIZE, PAGE_BTR_SEG_LEAF, PAGE_BTR_SEG_TOP,
    # Record format
    REC_N_NEW_EXTRA_BYTES, REC_N_OLD_EXTRA_BYTES,
    PAGE_NEW_INFIMUM_OFFSET, PAGE_NEW_SUPREMUM_OFFSET,
    PAGE_OLD_INFIMUM_OFFSET, PAGE_OLD_SUPREMUM_OFFSET,
    INFIMUM_DATA, SUPREMUM_DATA,
    REC_OFFS_SQL_NULL, REC_OFFS_EXTERNAL,
    REC_INFO_DELETED_FLAG,
    REC_STATUS_ORDINARY, REC_STATUS_INFIMUM, REC_STATUS_SUPREMUM,
    REC_STATUS_NODE_PTR,
    FIL_NULL,
)
from parser.checksum import mach_read_from_2, mach_read_from_4, mach_read_from_8

logger = logging.getLogger(__name__)


@dataclass
class InnoDBPage:
    """Represents a parsed InnoDB page."""
    page_type: int = 0
    page_no: int = 0
    space_id: int = 0
    lsn: int = 0
    prev_page: int = 0
    next_page: int = 0
    level: int = 0
    index_id: int = 0
    n_recs: int = 0
    n_heap: int = 0
    heap_top: int = 0
    free_offset: int = 0
    garbage_bytes: int = 0
    is_compact: bool = True
    checksum_algo: int = 0
    records: List['InnoDBRecord'] = field(default_factory=list)
    deleted_records: List['InnoDBRecord'] = field(default_factory=list)
    raw_data: bytes = b''


@dataclass
class InnoDBRecord:
    """Represents a parsed InnoDB record."""
    offset: int = 0               # Offset within page
    deleted: bool = False          # Delete-marked flag
    is_compact: bool = True        # COMPACT/DYNAMIC vs REDUNDANT format
    n_owned: int = 0              # Number of records owned
    heap_no: int = 0              # Heap number
    next_rec_offset: int = 0       # Offset to next record
    field_values: List[Any] = field(default_factory=list)
    field_nulls: List[bool] = field(default_factory=list)
    field_externals: List[bool] = field(default_factory=list)
    trx_id: int = 0               # Transaction ID (clustered index only)
    roll_ptr: int = 0             # Rollback pointer (clustered index only)
    data_size: int = 0            # Total data size
    raw_data: bytes = b''


def parse_film_header(page: bytes) -> Dict[str, int]:
    """Parse the FIL (file) header of an InnoDB page."""
    if len(page) < 38:
        return {}

    return {
        'checksum': mach_read_from_4(page, FIL_PAGE_SPACE_OR_CHKSUM),
        'page_no': mach_read_from_4(page, FIL_PAGE_OFFSET),
        'prev_page': mach_read_from_4(page, FIL_PAGE_PREV),
        'next_page': mach_read_from_4(page, FIL_PAGE_NEXT),
        'lsn': mach_read_from_8(page, FIL_PAGE_LSN),
        'page_type': mach_read_from_2(page, FIL_PAGE_TYPE),
        'flush_lsn': mach_read_from_8(page, FIL_PAGE_FILE_FLUSH_LSN),
        'space_id': mach_read_from_4(page, FIL_PAGE_ARCH_LOG_NO_OR_SPACE_ID),
    }


def is_compact_page(page: bytes) -> bool:
    """Check if page uses COMPACT/DYNAMIC (new) format vs REDUNDANT (old) format."""
    n_heap = mach_read_from_4(page, PAGE_HEADER + PAGE_N_HEAP)
    return bool(n_heap & 0x80000000)


def validate_infimum_supremum(page: bytes) -> bool:
    """Validate the infimum and supremum records on a page."""
    compact = is_compact_page(page)

    if compact:
        inf_offset = PAGE_NEW_INFIMUM_OFFSET
        sup_offset = PAGE_NEW_SUPREMUM_OFFSET
    else:
        inf_offset = PAGE_OLD_INFIMUM_OFFSET
        sup_offset = PAGE_OLD_SUPREMUM_OFFSET

    # Check infimum
    if inf_offset + len(INFIMUM_DATA) > UNIV_PAGE_SIZE:
        return False
    infimum = page[inf_offset:inf_offset + len(INFIMUM_DATA)]
    if infimum != INFIMUM_DATA:
        return False

    # Check supremum
    if sup_offset + len(SUPREMUM_DATA) > UNIV_PAGE_SIZE:
        return False
    supremum = page[sup_offset:sup_offset + len(SUPREMUM_DATA)]
    if supremum != SUPREMUM_DATA:
        return False

    return True


def is_valid_index_page(page: bytes) -> bool:
    """Check if the page is a valid InnoDB index page."""
    if len(page) != UNIV_PAGE_SIZE:
        return False

    # Check page type
    page_type = mach_read_from_2(page, FIL_PAGE_TYPE)
    if page_type not in INDEX_PAGE_TYPES:
        return False

    # Check page number
    page_no = mach_read_from_4(page, FIL_PAGE_OFFSET)
    if page_no == 0:
        return False

    # Validate infimum/supremum
    if not validate_infimum_supremum(page):
        return False

    return True


def get_record_pointers(page: bytes) -> List[int]:
    """
    Walk the record chain on a valid page and return offsets of all user records.
    Follows the linked list from infimum to supremum.
    """
    compact = is_compact_page(page)
    pointers = []

    if compact:
        inf_offset = PAGE_NEW_INFIMUM_OFFSET
        sup_offset = PAGE_NEW_SUPREMUM_OFFSET
    else:
        inf_offset = PAGE_OLD_INFIMUM_OFFSET
        sup_offset = PAGE_OLD_SUPREMUM_OFFSET

    # Get first record after infimum
    next_offset_bytes = inf_offset - 2
    current = mach_read_from_2(page, next_offset_bytes)

    if compact:
        current = inf_offset + current
    else:
        current = current  # In redundant format, offset is absolute

    visited = set()
    max_records = UNIV_PAGE_SIZE // 5  # Safety limit

    while current != sup_offset and len(pointers) < max_records:
        if current < 2 or current > UNIV_PAGE_SIZE:
            break
        if current in visited:
            break

        visited.add(current)
        pointers.append(current)

        # Get next record
        next_offset_bytes = current - 2
        next_val = mach_read_from_2(page, next_offset_bytes)

        if compact:
            current = current + next_val
        else:
            current = next_val

    return pointers


def get_free_list_records(page: bytes) -> List[int]:
    """
    Get records from the free list (potentially containing deleted records).
    InnoDB maintains a free list of deleted record space.
    """
    compact = is_compact_page(page)
    free_pointers = []

    free_offset = mach_read_from_2(page, PAGE_HEADER + PAGE_FREE)
    if free_offset == 0 or free_offset > UNIV_PAGE_SIZE:
        return free_pointers

    visited = set()
    current = free_offset
    max_records = UNIV_PAGE_SIZE // 5

    while current != 0 and current != FIL_NULL and len(free_pointers) < max_records:
        if current < 2 or current > UNIV_PAGE_SIZE:
            break
        if current in visited:
            break

        visited.add(current)
        free_pointers.append(current)

        # Next free record - stored at offset - 4 for compact, offset for old
        if compact:
            # In compact format, next free pointer is at current - 4
            next_free = mach_read_from_2(page, current - 4)
        else:
            next_free = mach_read_from_2(page, current - 4)

        current = next_free

    return free_pointers


def parse_record_header(page: bytes, offset: int, compact: bool) -> Tuple[int, int, int, int]:
    """
    Parse the extra bytes of a record header.
    Returns (status, n_owned, heap_no, next_rec_offset)
    """
    if compact:
        # COMPACT/DYNAMIC: 5 extra bytes
        # byte[0]: info_bits (bit 0 = deleted flag)
        # byte[1]: n_owned
        # byte[2-3]: heap_no (2 bytes)
        # byte[-1]: next record offset (2 bytes, stored before origin)
        origin = offset
        info_bits = page[origin - REC_N_NEW_EXTRA_BYTES]
        n_owned = page[origin - REC_N_NEW_EXTRA_BYTES + 1]
        heap_no = mach_read_from_2(page, origin - REC_N_NEW_EXTRA_BYTES + 2)
        next_rec = mach_read_from_2(page, origin - 2)
        status = (heap_no >> 7) & 0x03  # Extract status bits
        heap_no = heap_no & 0x7FFF  # Clear status bits
    else:
        # REDUNDANT: 6 extra bytes
        origin = offset
        info_byte = page[origin - REC_N_OLD_EXTRA_BYTES]
        n_owned = page[origin - REC_N_OLD_EXTRA_BYTES + 1]
        next_rec = mach_read_from_2(page, origin - 2)
        status = info_byte & 0x03
        heap_no = mach_read_from_2(page, origin - REC_N_OLD_EXTRA_BYTES + 2) & 0x7FFF

    deleted = bool(info_bits & REC_INFO_DELETED_FLAG)
    return status, n_owned, heap_no, next_rec, deleted


def parse_record_offsets_compact(page: bytes, origin: int, n_fields: int,
                                  n_nullable: int) -> Tuple[List[int], List[bool], List[bool]]:
    """
    Parse COMPACT/DYNAMIC record field offsets.
    Returns (offsets, null_flags, extern_flags)
    """
    offsets = [0]  # First field at offset 0 from origin
    null_flags = []
    extern_flags = []

    # Read null bitmap and variable-length field lengths
    nulls = origin - REC_N_NEW_EXTRA_BYTES - 1
    lens = nulls - ((n_nullable + 7) // 8)
    offs = 0
    null_mask = 1
    null_byte_idx = 0

    for i in range(n_fields):
        if i < n_nullable:
            # Check null flag
            if null_mask == 1:
                null_byte = page[nulls - null_byte_idx]
                null_byte_idx += 1
                null_mask = 256

            if null_byte & (null_mask >> 8):
                null_mask <<= 1
                null_flags.append(True)
                offsets.append(offs | REC_OFFS_SQL_NULL)
                extern_flags.append(False)
                continue
            null_mask <<= 1
            null_flags.append(False)

        # For compact format, variable-length fields have length stored
        # We need the field definitions to know which are variable
        # This is a simplified parser - actual field parsing needs table definition
        offsets.append(offs)
        extern_flags.append(False)

    return offsets, null_flags, extern_flags


def scan_page_for_records(page: bytes, table_fields: List[Dict] = None) -> Tuple[List[InnoDBRecord], List[InnoDBRecord]]:
    """
    Scan a page for valid records.
    Returns (active_records, deleted_records)
    """
    active_records = []
    deleted_records = []

    if not is_valid_index_page(page):
        return active_records, deleted_records

    compact = is_compact_page(page)

    # Get record chain pointers
    chain_records = get_record_pointers(page)
    free_records = get_free_list_records(page)

    all_offsets = set(chain_records + free_records)

    for offset in all_offsets:
        try:
            record = parse_record_at(page, offset, compact, table_fields)
            if record is None:
                continue
            if record.deleted:
                deleted_records.append(record)
            else:
                active_records.append(record)
        except Exception as e:
            logger.debug(f"Failed to parse record at offset {offset}: {e}")
            continue

    return active_records, deleted_records


def parse_record_at(page: bytes, offset: int, compact: bool,
                     table_fields: List[Dict] = None) -> Optional[InnoDBRecord]:
    """
    Try to parse a record at the given offset.
    Returns InnoDBRecord or None if the record appears invalid.
    """
    if offset < 2 or offset >= UNIV_PAGE_SIZE - 2:
        return None

    try:
        result = parse_record_header(page, offset, compact)
        status, n_owned, heap_no, next_rec, deleted = result
    except Exception:
        return None

    # Only process ordinary records
    if status != REC_STATUS_ORDINARY:
        return None

    rec = InnoDBRecord(
        offset=offset,
        deleted=deleted,
        is_compact=compact,
        n_owned=n_owned,
        heap_no=heap_no,
        next_rec_offset=next_rec,
    )

    rec.raw_data = page[offset:offset + 200]  # Capture first 200 bytes for analysis

    return rec
