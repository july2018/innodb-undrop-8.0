"""
SDI (Serialized Dictionary Information) Parser for MySQL 8.0
MySQL 8.0 stores table metadata in SDI pages within .ibd files.

The SDI is stored as a compressed record in an SDI B-tree (index type 17853).
Each SDI record contains a serialized JSON representation of the table metadata.
"""

import json
import struct
import logging
import zlib
from typing import Optional, Dict, List, Any

from utils.config import (
    UNIV_PAGE_SIZE,
    FIL_PAGE_INDEX, FIL_PAGE_SDI,
    FIL_PAGE_OFFSET, FIL_PAGE_TYPE,
    PAGE_HEADER, PAGE_INDEX_ID, PAGE_LEVEL, PAGE_N_HEAP,
    REC_N_NEW_EXTRA_BYTES,
    INFIMUM_DATA,
)
from parser.checksum import mach_read_from_2, mach_read_from_4, mach_read_from_8

logger = logging.getLogger(__name__)


def is_sdi_page(page: bytes) -> bool:
    """Check if a page is an SDI (Serialized Dictionary Information) page."""
    if len(page) != UNIV_PAGE_SIZE:
        return False
    page_type = mach_read_from_2(page, FIL_PAGE_TYPE)
    return page_type == FIL_PAGE_SDI


def extract_sdi_records_from_page(page: bytes) -> List[bytes]:
    """
    Extract raw SDI records from an SDI page.
    SDI records are stored in the same COMPACT format as regular index records,
    but contain serialized table metadata.
    """
    if not is_sdi_page(page):
        return []

    records = []
    compact = True  # SDI pages always use compact format
    inf_offset = 99  # PAGE_NEW_INFIMUM_OFFSET

    if inf_offset + 8 > UNIV_PAGE_SIZE:
        return []

    if page[inf_offset:inf_offset + 8] != INFIMUM_DATA:
        return []

    # Walk the record chain
    current_offset = mach_read_from_2(page, inf_offset - 2)
    current = inf_offset + current_offset  # Compact format: relative offset
    sup_offset = 112  # PAGE_NEW_SUPREMUM_OFFSET

    visited = set()
    max_records = 100  # SDI should have few records per page

    while current != sup_offset and len(records) < max_records:
        if current < 2 or current > UNIV_PAGE_SIZE or current in visited:
            break
        visited.add(current)

        try:
            # Parse record header
            info_bits = page[current - REC_N_NEW_EXTRA_BYTES]
            n_owned = page[current - REC_N_NEW_EXTRA_BYTES + 1]
            next_offset = mach_read_from_2(page, current - 2)

            # In COMPACT format, the SDI record data follows the header
            # The SDI data is a serialized blob (with length prefix)
            rec_start = current

            # Try to extract the record data
            rec_data = extract_sdi_record_data(page, current)
            if rec_data:
                records.append(rec_data)

            current = current + next_offset

        except Exception as e:
            logger.debug(f"Error parsing SDI record at offset {current}: {e}")
            break

    return records


def extract_sdi_record_data(page: bytes, offset: int) -> Optional[bytes]:
    """
    Extract the raw SDI data from a record at the given offset.
    SDI records in MySQL 8.0 have a specific format:
    - SDI type (4 bytes)
    - SDI version (4 bytes)
    - SDI key (variable)
    - SDI data (compressed or uncompressed)
    """
    try:
        # The SDI record is a COMPACT record
        # After the record origin, we have:
        # - Primary key fields (type + id)
        # - The SDI JSON blob

        # SDI record structure (from MySQL 8.0 source dict0sdi.cc):
        # Field 0: SDI_TYPE (INT, 4 bytes)
        # Field 1: SDI_VERSION (INT, 4 bytes)
        # Field 2: SDI_KEY (VARCHAR)
        # Field 3: SDI_DATA (BLOB/LONGBLOB - compressed JSON)

        # For COMPACT format, skip to the data area
        # The record origin points to the first byte of data after the header
        data_start = offset

        # Read type and version
        if data_start + 8 > UNIV_PAGE_SIZE:
            return None

        sdi_type = mach_read_from_4(page, data_start)
        sdi_version = mach_read_from_4(page, data_start + 4)

        # We need to parse the variable-length fields
        # This is simplified - the actual parsing needs table definition
        # Let's try to find JSON in the remaining page data
        remaining = page[data_start + 8:offset + 8000]

        # Look for JSON-like content (SDI data is JSON)
        json_start = find_json_start(remaining)
        if json_start >= 0:
            # Try to extract valid JSON
            json_data = remaining[json_start:]
            return try_parse_sdi_json(json_data)

        return None

    except Exception as e:
        logger.debug(f"Error extracting SDI data: {e}")
        return None


def find_json_start(data: bytes) -> int:
    """Find the start of JSON data in a byte sequence."""
    # SDI JSON starts with '{' and may have leading length bytes
    for i in range(min(len(data), 500)):
        if data[i:i + 1] == b'{':
            # Check if this looks like valid JSON start
            try:
                # Try to find a matching closing brace
                depth = 0
                for j in range(i, min(len(data), i + 64000)):
                    if data[j:j + 1] == b'{':
                        depth += 1
                    elif data[j:j + 1] == b'}':
                        depth -= 1
                        if depth == 0:
                            return i
            except Exception:
                continue
    return -1


def try_parse_sdi_json(data: bytes) -> Optional[bytes]:
    """
    Try to parse the SDI JSON data, handling potential compression.
    Returns the raw JSON bytes if successful.
    """
    # Try raw JSON first
    try:
        # Find complete JSON object
        depth = 0
        end = -1
        for i in range(len(data)):
            if data[i:i + 1] == b'{':
                depth += 1
            elif data[i:i + 1] == b'}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break

        if end > 0:
            json_str = data[:end].decode('utf-8', errors='replace')
            json.loads(json_str)  # Validate it's valid JSON
            return data[:end]
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    # Try decompressed
    try:
        decompressed = zlib.decompress(data)
        json_str = decompressed.decode('utf-8', errors='replace')
        json.loads(json_str)
        return decompressed
    except Exception:
        pass

    return None


def parse_sdi_to_table_info(sdi_json: bytes) -> Dict[str, Any]:
    """
    Parse SDI JSON into table information.
    Returns a dict with table name, column definitions, etc.
    """
    try:
        sdi = json.loads(sdi_json.decode('utf-8', errors='replace'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.error(f"Failed to parse SDI JSON: {e}")
        return {}

    # SDI structure in MySQL 8.0:
    # {
    #   "mysqld_version_id": 80046,
    #   "dd_object": {
    #     "name": "table_name",
    #     "mysql_version_id": 80046,
    #     "options": {...},
    #     "columns": [...],
    #     "indexes": [...],
    #     "foreign_keys": [...],
    #     "tablespace": {...},
    #     ...
    #   }
    # }

    table_info = {}

    dd_object = sdi.get('dd_object', {})
    table_info['name'] = dd_object.get('name', '')
    table_info['schema'] = dd_object.get('schema', '')
    table_info['mysql_version'] = sdi.get('mysqld_version_id', 0)
    table_info['engine'] = 'InnoDB'
    table_info['columns'] = []

    # Parse columns
    for col in dd_object.get('columns', []):
        column_info = {
            'name': col.get('name', ''),
            'type': col.get('type', ''),
            'is_nullable': col.get('is_nullable', True),
            'is_auto_increment': col.get('is_auto_increment', False),
            'char_length': col.get('char_length', 0),
            'numeric_precision': col.get('numeric_precision', 0),
            'numeric_scale': col.get('numeric_scale', None),
            'is_unsigned': col.get('is_unsigned', False),
            'generation_expression': col.get('generation_expression', ''),
            'hidden': col.get('hidden', 0),
        }

        # Map internal type to MySQL type
        column_info['mysql_type'] = map_column_type(col)
        column_info['fixed_length'] = get_fixed_length(col)
        column_info['max_length'] = get_max_length(col)
        column_info['is_variable'] = is_variable_length(col)

        table_info['columns'].append(column_info)

    # Parse indexes
    table_info['indexes'] = []
    for idx in dd_object.get('indexes', []):
        index_info = {
            'name': idx.get('name', ''),
            'type': idx.get('type', 'BTREE'),
            'is_primary': idx.get('is_primary', False),
            'is_unique': idx.get('is_unique', False),
            'columns': [c.get('name', '') for c in idx.get('columns', [])],
        }
        table_info['indexes'].append(index_info)

    # Primary key columns
    table_info['primary_key'] = []
    for idx in table_info['indexes']:
        if idx['is_primary']:
            table_info['primary_key'] = idx['columns']
            break

    # Try to generate CREATE TABLE statement
    table_info['create_table'] = generate_create_table(table_info)

    return table_info


def map_column_type(col: Dict) -> str:
    """Map internal column type to MySQL type string."""
    col_type = col.get('type', '')
    if col_type.startswith('MYSQL_TYPE_'):
        return col_type.replace('MYSQL_TYPE_', '')
    return col_type


def get_fixed_length(col: Dict) -> int:
    """Get the fixed length of a column (0 for variable-length)."""
    # Variable-length types
    var_types = {'VARCHAR', 'CHAR', 'BINARY', 'VARBINARY',
                 'BLOB', 'TEXT', 'JSON', 'GEOMETRY',
                 'ENUM', 'SET', 'DECIMAL', 'NUMERIC'}
    col_type = map_column_type(col).upper()
    if col_type in var_types:
        return 0

    # Fixed-length types
    fixed_map = {
        'TINYINT': 1, 'SMALLINT': 2, 'MEDIUMINT': 3,
        'INT': 4, 'INTEGER': 4, 'BIGINT': 8,
        'FLOAT': 4, 'DOUBLE': 8,
        'DATE': 3, 'TIME': 3, 'YEAR': 1,
        'TIMESTAMP': 4, 'DATETIME': 8,
        'BIT': 1,
    }
    return fixed_map.get(col_type, 0)


def get_max_length(col: Dict) -> int:
    """Get the maximum length of a variable-length column."""
    char_length = col.get('char_length', 0)
    numeric_precision = col.get('numeric_precision', 0)
    col_type = map_column_type(col).upper()

    if col_type in ('VARCHAR', 'CHAR', 'BINARY', 'VARBINARY'):
        return char_length
    elif col_type in ('BLOB', 'TEXT', 'JSON', 'GEOMETRY'):
        return char_length or 65535
    elif col_type in ('TINYBLOB', 'TINYTEXT'):
        return 255
    elif col_type in ('MEDIUMBLOB', 'MEDIUMTEXT'):
        return 16777215
    elif col_type in ('LONGBLOB', 'LONGTEXT'):
        return 4294967295
    elif col_type in ('DECIMAL', 'NUMERIC'):
        return (numeric_precision + 2) if numeric_precision else 0
    return 0


def is_variable_length(col: Dict) -> bool:
    """Check if a column is variable-length."""
    var_types = {'VARCHAR', 'VARBINARY', 'BLOB', 'TEXT', 'JSON',
                 'GEOMETRY', 'ENUM', 'SET'}
    col_type = map_column_type(col).upper()
    # CHAR is fixed-length in InnoDB COMPACT format (padded)
    return col_type in var_types


def generate_create_table(table_info: Dict) -> str:
    """Generate a CREATE TABLE statement from parsed SDI info."""
    if not table_info.get('name'):
        return ''

    lines = []
    lines.append(f"CREATE TABLE `{table_info['name']}` (")

    col_defs = []
    for col in table_info.get('columns', []):
        col_def = build_column_definition(col)
        if col_def:
            col_defs.append(f"  {col_def}")

    # Add primary key
    if table_info.get('primary_key'):
        pk_cols = ', '.join(f'`{c}`' for c in table_info['primary_key'])
        col_defs.append(f"  PRIMARY KEY ({pk_cols})")

    lines.append(',\n'.join(col_defs))
    lines.append(') ENGINE=InnoDB;')

    return '\n'.join(lines)


def build_column_definition(col: Dict) -> str:
    """Build a single column definition for CREATE TABLE."""
    name = col.get('name', '')
    if not name:
        return ''

    col_type = map_column_type(col).upper()
    max_len = col.get('max_length', 0) or col.get('char_length', 0)
    nullable = col.get('is_nullable', True)
    auto_inc = col.get('is_auto_increment', False)
    unsigned = col.get('is_unsigned', False)

    # Build type string
    if col_type in ('VARCHAR', 'CHAR'):
        type_str = f"{col_type}({max_len})"
    elif col_type in ('BINARY', 'VARBINARY'):
        type_str = f"{col_type}({max_len})"
    elif col_type in ('TINYINT', 'SMALLINT', 'MEDIUMINT', 'INT', 'INTEGER', 'BIGINT'):
        type_str = col_type
        if max_len and col_type not in ('INT', 'INTEGER'):
            type_str = f"{col_type}({max_len})"
        if unsigned:
            type_str += ' UNSIGNED'
    elif col_type in ('FLOAT', 'DOUBLE'):
        type_str = col_type
    elif col_type in ('DECIMAL', 'NUMERIC'):
        precision = col.get('numeric_precision', 10)
        scale = col.get('numeric_scale', 0)
        type_str = f"DECIMAL({precision},{scale})"
    elif col_type in ('DATE', 'TIME', 'DATETIME', 'TIMESTAMP'):
        type_str = col_type
    elif col_type in ('YEAR'):
        type_str = f"YEAR(4)"
    elif col_type in ('TINYBLOB', 'BLOB', 'MEDIUMBLOB', 'LONGBLOB'):
        type_str = col_type
    elif col_type in ('TINYTEXT', 'TEXT', 'MEDIUMTEXT', 'LONGTEXT'):
        type_str = col_type
    elif col_type == 'BIT':
        type_str = f"BIT({max_len})"
    elif col_type == 'JSON':
        type_str = 'JSON'
    elif col_type == 'GEOMETRY':
        type_str = 'GEOMETRY'
    else:
        type_str = col_type

    null_str = '' if nullable else ' NOT NULL'
    auto_str = ' AUTO_INCREMENT' if auto_inc else ''

    return f"`{name}` {type_str}{null_str}{auto_str}"


def extract_table_metadata_from_ibd(ibd_path: str) -> Dict[str, Any]:
    """
    Extract table metadata from an .ibd file by scanning for SDI pages.
    Returns parsed table info if found.
    """
    from parser.page_scanner import scan_file_for_pages

    result = scan_file_for_pages(ibd_path)
    sdi_pages = [p for p in result.pages if p.page_type == FIL_PAGE_SDI]

    if not sdi_pages:
        logger.warning(f"No SDI pages found in {ibd_path}")
        return {}

    for sdi_page in sdi_pages:
        sdi_records = extract_sdi_records_from_page(sdi_page.raw_data)
        for sdi_data in sdi_records:
            table_info = parse_sdi_to_table_info(sdi_data)
            if table_info:
                return table_info

    return {}
