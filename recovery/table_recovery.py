"""
Table Recovery Module for MySQL 8.0 InnoDB
Recovers dropped tables and deleted rows from InnoDB data files
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from utils.config import (
    UNIV_PAGE_SIZE,
    FIL_PAGE_INDEX, FIL_PAGE_SDI,
    PAGE_LEVEL, PAGE_N_HEAP,
    PAGE_HEADER, PAGE_GARBAGE, PAGE_FREE, PAGE_N_RECS,
    REC_N_NEW_EXTRA_BYTES,
    REC_INFO_DELETED_FLAG,
)
from parser.checksum import mach_read_from_2, mach_read_from_4, mach_read_from_8
from parser.page_scanner import (
    scan_file_for_pages, scan_all_ibd_files,
    ScanResult,
)
from parser.page_parser import (
    InnoDBPage, InnoDBRecord,
    is_valid_index_page, get_record_pointers,
    get_free_list_records, is_compact_page,
)
from parser.sdi_parser import (
    extract_sdi_records_from_page,
    parse_sdi_to_table_info,
    extract_table_metadata_from_ibd,
)
from parser.record_parser import (
    FieldDefinition, ParsedRecord,
    parse_create_table, parse_record_compact,
)

logger = logging.getLogger(__name__)


@dataclass
class RecoveryResult:
    """Result of a table recovery operation."""
    table_name: str = ''
    database_name: str = ''
    create_table: str = ''
    total_pages_scanned: int = 0
    valid_pages: int = 0
    leaf_pages: int = 0
    records_recovered: int = 0
    deleted_records_recovered: int = 0
    active_records_recovered: int = 0
    records: List[Dict[str, Any]] = field(default_factory=list)
    deleted_records: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    table_metadata: Dict = field(default_factory=dict)
    fields: List[FieldDefinition] = field(default_factory=list)


def recover_dropped_table(datadir: str, database: str, table: str,
                           create_table: str = None,
                           checksum_algo: int = None,
                           recover_deleted_only: bool = False) -> RecoveryResult:
    """
    Recover a dropped table from InnoDB data files.

    When a table is DROPped in MySQL 8.0:
    1. The .ibd file is typically deleted from disk
    2. But the data may still exist in ibdata1 (if the table was in the system tablespace)
       OR the .ibd file may still exist (if the OS hasn't reused the space)
    3. The data dictionary entries are removed

    Strategy:
    - First, check if the .ibd file still exists on disk
    - If not, scan ibdata1 for pages matching the table's index ID
    - If no CREATE TABLE is provided, try to extract from SDI pages
    - Parse all leaf pages and extract records
    """
    result = RecoveryResult(
        table_name=table,
        database_name=database,
    )

    logger.info(f"Starting recovery of {database}.{table}")
    logger.info(f"  Data directory: {datadir}")

    # Step 1: Find the .ibd file or scan ibdata1
    ibd_path = os.path.join(datadir, database, f'{table}.ibd')
    files_to_scan = []

    if os.path.exists(ibd_path):
        logger.info(f"  Found .ibd file: {ibd_path}")
        files_to_scan.append(ibd_path)
    else:
        logger.warning(f"  .ibd file not found at {ibd_path}")
        logger.info(f"  Will scan ibdata1 and all .ibd files for recovery")

        # Scan ibdata1
        ibdata_path = os.path.join(datadir, 'ibdata1')
        if os.path.exists(ibdata_path):
            files_to_scan.append(ibdata_path)
            result.warnings.append(
                "Table .ibd file was deleted. Scanning ibdata1 for data pages. "
                "Recovery may find pages from multiple tables - results need manual verification."
            )
        else:
            result.errors.append(f"Neither {ibd_path} nor ibdata1 found. Cannot recover.")
            return result

        # Also scan all other .ibd files (the table might have been moved)
        db_dir = os.path.join(datadir, database)
        if os.path.isdir(db_dir):
            for fname in os.listdir(db_dir):
                if fname.endswith('.ibd'):
                    fpath = os.path.join(db_dir, fname)
                    if fpath not in files_to_scan:
                        files_to_scan.append(fpath)

    # Step 2: Get table structure
    if create_table:
        logger.info("  Using provided CREATE TABLE statement")
        result.create_table = create_table
        result.fields = parse_create_table(create_table)
    else:
        # Try to extract from SDI
        logger.info("  No CREATE TABLE provided, attempting SDI extraction")
        for fpath in files_to_scan:
            metadata = extract_table_metadata_from_ibd(fpath)
            if metadata and metadata.get('name', '').lower() == table.lower():
                logger.info(f"  Found table metadata in SDI: {fpath}")
                result.create_table = metadata.get('create_table', '')
                result.table_metadata = metadata
                result.fields = parse_create_table(result.create_table) if result.create_table else []
                break

        if not result.fields:
            result.warnings.append(
                "Could not determine table structure from SDI. "
                "Records will be parsed as raw hex. Provide --create-table for proper recovery."
            )

    # Step 3: Scan files for data pages
    all_pages = []
    for fpath in files_to_scan:
        logger.info(f"  Scanning: {fpath}")
        scan_result = scan_file_for_pages(
            fpath,
            checksum_algo=checksum_algo,
            include_deleted_pages=True,
        )
        result.total_pages_scanned += scan_result.total_pages
        result.valid_pages += scan_result.valid_pages

        if scan_result.encrypted:
            result.warnings.append(
                f"File {fpath} contains encrypted pages. "
                "Encrypted pages cannot be parsed without the encryption key."
            )

        for p in scan_result.pages:
            if p.page_type == FIL_PAGE_INDEX and p.level == 0:
                all_pages.append(p)

    result.leaf_pages = len(all_pages)
    logger.info(f"  Found {result.leaf_pages} leaf pages to parse")

    if not result.fields:
        # No table definition - do raw scan
        return _raw_scan_recovery(result, all_pages, recover_deleted_only)

    # Step 4: Parse records from leaf pages
    n_nullable = sum(1 for f in result.fields if f.is_nullable)
    is_clustered = any(f.is_primary_key for f in result.fields)

    for page in all_pages:
        try:
            _parse_page_records(result, page, result.fields, n_nullable,
                               is_clustered, recover_deleted_only)
        except Exception as e:
            result.errors.append(f"Error parsing page {page.page_no}: {e}")
            logger.error(f"  Error parsing page {page.page_no}: {e}")

    logger.info(f"  Recovery complete:")
    logger.info(f"    Active records: {result.active_records_recovered}")
    logger.info(f"    Deleted records: {result.deleted_records_recovered}")
    logger.info(f"    Total records: {result.records_recovered}")

    return result


def _raw_scan_recovery(result: RecoveryResult, pages: List[InnoDBPage],
                         deleted_only: bool) -> RecoveryResult:
    """
    Perform raw scanning without table definition.
    Tries to find any readable data patterns in pages.
    """
    for page in pages:
        compact = page.is_compact
        garbage = page.garbage_bytes

        if garbage > 0:
            # Page has deleted data
            result.warnings.append(
                f"Page {page.page_no}: {garbage} bytes of deleted data found"
            )

    return result


def _parse_page_records(result: RecoveryResult, page: InnoDBPage,
                        fields: List[FieldDefinition], n_nullable: int,
                        is_clustered: bool, deleted_only: bool):
    """Parse all records from a single leaf page."""
    compact = page.is_compact

    if compact:
        inf_offset = 99   # PAGE_NEW_INFIMUM_OFFSET
        sup_offset = 112  # PAGE_NEW_SUPREMUM_OFFSET
    else:
        inf_offset = 101  # PAGE_OLD_INFIMUM_OFFSET
        sup_offset = 120  # PAGE_OLD_SUPREMUM_OFFSET

    # Walk record chain
    next_offset = mach_read_from_2(page.raw_data, inf_offset - 2)
    current = inf_offset + next_offset if compact else next_offset

    visited = set()
    max_records = 2000  # Safety limit

    while current != sup_offset and len(visited) < max_records:
        if current < 2 or current >= UNIV_PAGE_SIZE or current in visited:
            break
        visited.add(current)

        try:
            # Get record info bits (deleted flag)
            # In MySQL 8.0 compact format: info_bits is upper nibble of byte at rec-5
            # REC_INFO_DELETED_FLAG = 0x20 (bit 5 of byte at current-5)
            extra_start = current - REC_N_NEW_EXTRA_BYTES
            info_bits = page.raw_data[extra_start] & 0xF0
            deleted = bool(info_bits & REC_INFO_DELETED_FLAG)

            if deleted_only and not deleted:
                # Skip non-deleted records
                next_val = mach_read_from_2(page.raw_data, current - 2)
                current = current + next_val if compact else next_val
                continue

            # Parse the record
            parsed = parse_record_compact(
                page.raw_data, current, fields, is_clustered
            )

            if parsed and parsed.field_values:
                parsed.page_no = page.page_no
                record_dict = {
                    '_page': page.page_no,
                    '_offset': current,
                    '_deleted': deleted,
                    **parsed.field_values,
                }

                if deleted:
                    result.deleted_records.append(record_dict)
                    result.deleted_records_recovered += 1
                else:
                    result.records.append(record_dict)
                    result.active_records_recovered += 1

                result.records_recovered += 1

        except Exception as e:
            logger.debug(f"  Error at offset {current}: {e}")

        # Move to next record
        next_val = mach_read_from_2(page.raw_data, current - 2)
        current = current + next_val if compact else next_val

    # Also scan free list for deleted records
    free_offset = mach_read_from_2(page.raw_data, PAGE_HEADER + PAGE_FREE)
    if free_offset > 0 and free_offset < UNIV_PAGE_SIZE:
        _scan_free_list(result, page, fields, is_clustered, free_offset, compact)


def _scan_free_list(result: RecoveryResult, page: InnoDBPage,
                     fields: List[FieldDefinition], is_clustered: bool,
                     start_offset: int, compact: bool):
    """Scan the free record list for recoverable deleted records."""
    current = start_offset
    visited = set()
    max_records = 200

    while current != 0 and current != 0xFFFFFFFF and len(visited) < max_records:
        if current < 2 or current > UNIV_PAGE_SIZE or current in visited:
            break
        visited.add(current)

        try:
            # Try to parse as a record
            parsed = parse_record_compact(
                page.raw_data, current, fields, is_clustered
            )

            if parsed and parsed.field_values:
                parsed.page_no = page.page_no
                record_dict = {
                    '_page': page.page_no,
                    '_offset': current,
                    '_deleted': True,
                    '_from_free_list': True,
                    **parsed.field_values,
                }
                result.deleted_records.append(record_dict)
                result.deleted_records_recovered += 1
                result.records_recovered += 1

        except Exception:
            pass

        # Next free record
        next_free = mach_read_from_2(page.raw_data, current - 4)
        current = next_free


def scan_database_for_recoverable_tables(datadir: str, database: str) -> Dict[str, Dict]:
    """
    Scan a database directory and ibdata1 for all recoverable tables.
    Returns a dict mapping table names to their metadata.
    """
    tables = {}
    db_dir = os.path.join(datadir, database)

    # Scan all .ibd files for SDI metadata
    if os.path.isdir(db_dir):
        for fname in os.listdir(db_dir):
            if fname.endswith('.ibd'):
                ibd_path = os.path.join(db_dir, fname)
                try:
                    metadata = extract_table_metadata_from_ibd(ibd_path)
                    if metadata:
                        table_name = metadata.get('name', fname[:-4])
                        tables[table_name] = {
                            'ibd_path': ibd_path,
                            'metadata': metadata,
                        }
                except Exception as e:
                    logger.debug(f"Error reading SDI from {ibd_path}: {e}")

    # Also scan ibdata1
    ibdata_path = os.path.join(datadir, 'ibdata1')
    if os.path.exists(ibdata_path):
        scan_result = scan_file_for_pages(ibdata_path)
        for page in scan_result.pages:
            if page.page_type == FIL_PAGE_SDI:
                try:
                    sdi_records = extract_sdi_records_from_page(page.raw_data)
                    for sdi_data in sdi_records:
                        metadata = parse_sdi_to_table_info(sdi_data)
                        if metadata:
                            table_name = metadata.get('name', '')
                            if table_name and table_name not in tables:
                                tables[table_name] = {
                                    'ibd_path': ibdata_path,
                                    'in_ibdata': True,
                                    'metadata': metadata,
                                }
                except Exception as e:
                    logger.debug(f"Error parsing SDI page {page.page_no}: {e}")

    return tables


def recover_deleted_rows(datadir: str, database: str, table: str,
                          create_table: str = None,
                          checksum_algo: int = None) -> RecoveryResult:
    """
    Recover deleted (DELETE FROM) rows from a table.
    This scans the table's .ibd file for delete-marked records.
    """
    result = recover_dropped_table(
        datadir=datadir,
        database=database,
        table=table,
        create_table=create_table,
        checksum_algo=checksum_algo,
        recover_deleted_only=True,
    )
    return result
