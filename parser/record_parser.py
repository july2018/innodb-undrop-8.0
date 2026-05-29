"""
Record Parser for MySQL 8.0 InnoDB COMPACT/DYNAMIC Row Format
Parses actual record data from InnoDB leaf pages using table definition
"""

import struct
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass

from utils.config import (
    UNIV_PAGE_SIZE,
    REC_N_NEW_EXTRA_BYTES, REC_N_OLD_EXTRA_BYTES,
    REC_OFFS_SQL_NULL, REC_OFFS_EXTERNAL,
    REC_INFO_DELETED_FLAG,
    REC_STATUS_ORDINARY,
    PAGE_NEW_INFIMUM_OFFSET, PAGE_NEW_SUPREMUM_OFFSET,
    INFIMUM_DATA, SUPREMUM_DATA,
    DATA_CHAR, DATA_VARCHAR, DATA_BINARY, DATA_VARBINARY,
    DATA_TINY, DATA_SHORT, DATA_INT, DATA_LONG,
    DATA_FLOAT, DATA_DOUBLE, DATA_DECIMAL,
    DATA_BLOB, DATA_TEXT,
    DATA_DATE, DATA_DATETIME, DATA_TIMESTAMP, DATA_TIME, DATA_YEAR,
    DATA_BIT, DATA_ENUM, DATA_SET, DATA_JSON, DATA_GEOMETRY,
    DATA_UNKNOWN,
    MYSQL_TYPE_TINY, MYSQL_TYPE_SHORT, MYSQL_TYPE_LONG,
    MYSQL_TYPE_LONGLONG, MYSQL_TYPE_FLOAT, MYSQL_TYPE_DOUBLE,
    MYSQL_TYPE_DATE, MYSQL_TYPE_DATETIME, MYSQL_TYPE_TIMESTAMP,
    MYSQL_TYPE_TIME, MYSQL_TYPE_YEAR,
    MYSQL_TYPE_STRING, MYSQL_TYPE_VAR_STRING, MYSQL_TYPE_VARCHAR,
    MYSQL_TYPE_DECIMAL, MYSQL_TYPE_NEWDECIMAL,
    MYSQL_TYPE_BIT, MYSQL_TYPE_BLOB, MYSQL_TYPE_TINY_BLOB,
    MYSQL_TYPE_MEDIUM_BLOB, MYSQL_TYPE_LONG_BLOB,
    MYSQL_TYPE_JSON, MYSQL_TYPE_GEOMETRY,
    MYSQL_TYPE_ENUM, MYSQL_TYPE_SET,
)
from parser.checksum import mach_read_from_2, mach_read_from_4, mach_read_from_8

logger = logging.getLogger(__name__)


@dataclass
class FieldDefinition:
    """Definition of a table field for record parsing."""
    name: str = ''
    field_type: str = DATA_UNKNOWN
    mysql_type: int = MYSQL_TYPE_STRING
    is_nullable: bool = True
    is_unsigned: bool = False
    fixed_length: int = 0      # Fixed length for fixed-size types
    max_length: int = 0         # Max length for variable-size types
    is_variable: bool = False   # Variable-length field
    is_auto_increment: bool = False
    is_primary_key: bool = False
    char_length: int = 0
    numeric_precision: int = 0
    numeric_scale: int = 0
    decimal_digits: int = 0

    @property
    def needs_length_bytes(self) -> int:
        """Number of length bytes needed (1 or 2)."""
        if not self.is_variable:
            return 0
        if self.max_length > 255 or self.mysql_type in (
            MYSQL_TYPE_BLOB, MYSQL_TYPE_TINY_BLOB,
            MYSQL_TYPE_MEDIUM_BLOB, MYSQL_TYPE_LONG_BLOB,
            MYSQL_TYPE_JSON, MYSQL_TYPE_GEOMETRY,
        ):
            return 2
        return 1


@dataclass
class ParsedRecord:
    """A fully parsed InnoDB record with field values."""
    page_no: int = 0
    page_offset: int = 0
    deleted: bool = False
    field_values: Dict[str, Any] = None
    field_raw: Dict[str, bytes] = None
    trx_id: int = 0
    null_fields: List[str] = None
    external_fields: List[str] = None

    def __post_init__(self):
        if self.field_values is None:
            self.field_values = {}
        if self.field_raw is None:
            self.field_raw = {}
        if self.null_fields is None:
            self.null_fields = []
        if self.external_fields is None:
            self.external_fields = []


def parse_create_table(create_table_sql: str) -> List[FieldDefinition]:
    """
    Parse a CREATE TABLE statement into field definitions.
    This is a simplified parser that handles common MySQL data types.
    """
    import re

    fields = []
    primary_keys = []

    # Remove CREATE TABLE ... ( and trailing );
    sql = create_table_sql.strip()
    if sql.upper().startswith('CREATE TABLE'):
        # Extract the part between first ( and last )
        start = sql.index('(')
        end = sql.rindex(')')
        body = sql[start + 1:end]
    else:
        body = sql

    # Split by commas (but be careful with expressions in parentheses)
    parts = []
    depth = 0
    current = ''
    for ch in body:
        if ch == '(':
            depth += 1
            current += ch
        elif ch == ')':
            depth -= 1
            current += ch
        elif ch == ',' and depth == 0:
            parts.append(current.strip())
            current = ''
        else:
            current += ch
    if current.strip():
        parts.append(current.strip())

    for part in parts:
        part = part.strip()
        upper = part.upper()

        # Skip table-level constraints
        if upper.startswith(('PRIMARY KEY', 'KEY ', 'INDEX ', 'UNIQUE KEY',
                              'UNIQUE INDEX', 'CONSTRAINT', 'FOREIGN KEY',
                              'CHECK ')):
            # Extract primary key column names
            if upper.startswith('PRIMARY KEY'):
                match = re.search(r'PRIMARY\s+KEY\s*\(([^)]+)\)', part, re.IGNORECASE)
                if match:
                    pk_str = match.group(1)
                    primary_keys = [c.strip().strip('`') for c in pk_str.split(',')]
            continue

        # Parse column definition
        field = parse_column_def(part)
        if field:
            fields.append(field)

    # Mark primary key fields
    pk_set = set(primary_keys)
    for f in fields:
        if f.name in pk_set:
            f.is_primary_key = True

    return fields


def parse_column_def(col_def: str) -> Optional[FieldDefinition]:
    """Parse a single column definition string."""
    import re

    col_def = col_def.strip()
    if not col_def:
        return None

    # Extract column name
    parts = col_def.split(None, 1)
    if not parts:
        return None

    name = parts[0].strip('`"[]')
    rest = ' '.join(parts[1:]).upper() if len(parts) > 1 else ''

    if not rest:
        return None

    field = FieldDefinition(name=name)

    # Parse type
    type_pattern = r'(\w+)(?:\(([^)]+)\))?'
    match = re.match(type_pattern, rest)
    if not match:
        return None

    col_type = match.group(1)
    type_params = match.group(2)  # Parameters in parentheses

    # Map type
    field.mysql_type = map_mysql_type(col_type)
    field.field_type = map_field_type(col_type)

    # Parse type parameters
    if type_params:
        param_parts = [p.strip() for p in type_params.split(',')]
        if col_type in ('DECIMAL', 'NUMERIC', 'FIXED'):
            if len(param_parts) >= 1:
                field.numeric_precision = int(param_parts[0])
            if len(param_parts) >= 2:
                field.numeric_scale = int(param_parts[1])
            field.char_length = field.numeric_precision + 2
            field.max_length = field.char_length
        elif col_type in ('FLOAT', 'DOUBLE'):
            field.char_length = int(param_parts[0]) if param_parts else 0
        elif col_type == 'BIT':
            field.char_length = int(param_parts[0]) if param_parts else 0
            field.fixed_length = (field.char_length + 7) // 8
        elif col_type in ('ENUM', 'SET'):
            field.char_length = len(type_params)
            field.max_length = min(65535, max(len(p.strip("'\"") for p in param_parts), 1))
        else:
            try:
                field.char_length = int(param_parts[0])
                field.max_length = field.char_length
            except (ValueError, IndexError):
                pass

    # Determine fixed vs variable length
    field.is_variable = col_type in (
        'VARCHAR', 'VARBINARY', 'BLOB', 'TEXT', 'JSON',
        'GEOMETRY', 'ENUM', 'SET',
        'TINYBLOB', 'MEDIUMBLOB', 'LONGBLOB',
        'TINYTEXT', 'MEDIUMTEXT', 'LONGTEXT',
    )

    if not field.is_variable:
        field.fixed_length = get_type_fixed_length(col_type, field)

    # Parse modifiers
    if 'NOT NULL' in rest:
        field.is_nullable = False
    if 'UNSIGNED' in rest:
        field.is_unsigned = True
    if 'AUTO_INCREMENT' in rest:
        field.is_auto_increment = True
    if 'PRIMARY KEY' in rest:
        field.is_primary_key = True

    return field


def map_mysql_type(col_type: str) -> int:
    """Map MySQL type name to MySQL type code."""
    type_map = {
        'TINYINT': MYSQL_TYPE_TINY,
        'SMALLINT': MYSQL_TYPE_SHORT,
        'MEDIUMINT': 9,  # MYSQL_TYPE_INT24
        'INT': MYSQL_TYPE_LONG,
        'INTEGER': MYSQL_TYPE_LONG,
        'BIGINT': MYSQL_TYPE_LONGLONG,
        'FLOAT': MYSQL_TYPE_FLOAT,
        'DOUBLE': MYSQL_TYPE_DOUBLE,
        'DATE': MYSQL_TYPE_DATE,
        'DATETIME': MYSQL_TYPE_DATETIME,
        'TIMESTAMP': MYSQL_TYPE_TIMESTAMP,
        'TIME': MYSQL_TYPE_TIME,
        'YEAR': MYSQL_TYPE_YEAR,
        'VARCHAR': MYSQL_TYPE_VARCHAR,
        'CHAR': MYSQL_TYPE_STRING,
        'BINARY': MYSQL_TYPE_STRING,
        'VARBINARY': MYSQL_TYPE_VAR_STRING,
        'BLOB': MYSQL_TYPE_BLOB,
        'TEXT': MYSQL_TYPE_BLOB,
        'TINYBLOB': MYSQL_TYPE_TINY_BLOB,
        'TINYTEXT': MYSQL_TYPE_TINY_BLOB,
        'MEDIUMBLOB': MYSQL_TYPE_MEDIUM_BLOB,
        'MEDIUMTEXT': MYSQL_TYPE_MEDIUM_BLOB,
        'LONGBLOB': MYSQL_TYPE_LONG_BLOB,
        'LONGTEXT': MYSQL_TYPE_LONG_BLOB,
        'DECIMAL': MYSQL_TYPE_NEWDECIMAL,
        'NUMERIC': MYSQL_TYPE_NEWDECIMAL,
        'FIXED': MYSQL_TYPE_NEWDECIMAL,
        'BIT': MYSQL_TYPE_BIT,
        'JSON': MYSQL_TYPE_JSON,
        'GEOMETRY': MYSQL_TYPE_GEOMETRY,
        'ENUM': MYSQL_TYPE_ENUM,
        'SET': MYSQL_TYPE_SET,
    }
    return type_map.get(col_type.upper(), MYSQL_TYPE_STRING)


def map_field_type(col_type: str) -> str:
    """Map MySQL type name to internal field type."""
    type_map = {
        'TINYINT': DATA_TINY, 'SMALLINT': DATA_SHORT,
        'MEDIUMINT': DATA_INT, 'INT': DATA_INT, 'INTEGER': DATA_INT,
        'BIGINT': DATA_LONG,
        'FLOAT': DATA_FLOAT, 'DOUBLE': DATA_DOUBLE,
        'DATE': DATA_DATE, 'DATETIME': DATA_DATETIME,
        'TIMESTAMP': DATA_TIMESTAMP, 'TIME': DATA_TIME, 'YEAR': DATA_YEAR,
        'VARCHAR': DATA_VARCHAR, 'CHAR': DATA_CHAR,
        'BINARY': DATA_BINARY, 'VARBINARY': DATA_VARBINARY,
        'BLOB': DATA_BLOB, 'TEXT': DATA_TEXT,
        'TINYBLOB': DATA_BLOB, 'TINYTEXT': DATA_TEXT,
        'MEDIUMBLOB': DATA_BLOB, 'MEDIUMTEXT': DATA_TEXT,
        'LONGBLOB': DATA_BLOB, 'LONGTEXT': DATA_TEXT,
        'DECIMAL': DATA_DECIMAL, 'NUMERIC': DATA_DECIMAL,
        'BIT': DATA_BIT,
        'JSON': DATA_JSON, 'GEOMETRY': DATA_GEOMETRY,
        'ENUM': DATA_ENUM, 'SET': DATA_SET,
    }
    return type_map.get(col_type.upper(), DATA_UNKNOWN)


def get_type_fixed_length(col_type: str, field: FieldDefinition) -> int:
    """Get the fixed length for a fixed-size data type."""
    fixed_map = {
        'TINYINT': 1, 'SMALLINT': 2, 'MEDIUMINT': 3,
        'INT': 4, 'INTEGER': 4, 'BIGINT': 8,
        'FLOAT': 4, 'DOUBLE': 8,
        'DATE': 3, 'TIME': 3, 'YEAR': 1,
        'TIMESTAMP': 4, 'DATETIME': 5,
        'BIT': (field.char_length + 7) // 8 if field.char_length else 1,
    }
    return fixed_map.get(col_type.upper(), 0)


def parse_record_compact(page: bytes, origin: int, fields: List[FieldDefinition],
                         is_clustered: bool = True) -> Optional[ParsedRecord]:
    """
    Parse a COMPACT/DYNAMIC format record from a page.

    In COMPACT format record layout:
    - Variable-length field lengths (1 or 2 bytes each, stored before null bitmap)
    - NULL bitmap (1 bit per nullable field)
    - Record header (REC_N_NEW_EXTRA_BYTES = 5 bytes: info_bits, n_owned, heap_no, status)
    - Field data (in column order)
    - For clustered index: trx_id (6 bytes) + roll_ptr (7 bytes) after primary key
    """
    n_fields = len(fields)
    n_nullable = sum(1 for f in fields if f.is_nullable)
    n_var_fields = sum(1 for f in fields if f.is_variable)

    try:
        # Calculate positions relative to the record origin
        # REC_N_NEW_EXTRA_BYTES = 5 bytes before origin
        extra_start = origin - REC_N_NEW_EXTRA_BYTES

        # Info bits at extra_start
        info_bits = page[extra_start]
        deleted = bool(info_bits & REC_INFO_DELETED_FLAG)

        # Null bitmap: located before the extra bytes
        null_bitmap_size = (n_nullable + 7) // 8
        null_bitmap_start = extra_start - 1  # Last null byte
        null_bitmap_bytes_start = null_bitmap_start - null_bitmap_size + 1

        # Variable-length field lengths: before null bitmap
        lens_start = null_bitmap_bytes_start - 1  # Start from last byte going backwards

        # Read field offsets
        field_offsets = []
        current_offset = 0
        lens_ptr = lens_start

        # Read null bitmap
        null_flags = {}
        null_mask = 1
        null_byte_offset = null_bitmap_bytes_start

        for i in range(n_fields):
            field = fields[i]

            # Check NULL
            if field.is_nullable:
                if null_mask == 1:
                    if null_byte_offset < 0 or null_byte_offset >= len(page):
                        return None
                    current_null_byte = page[null_byte_offset]
                    null_byte_offset += 1
                    null_mask = 256

                is_null = bool(current_null_byte & (null_mask >> 8))
                null_mask <<= 1

                if is_null:
                    null_flags[i] = True
                    field_offsets.append(REC_OFFS_SQL_NULL)
                    continue

                null_flags[i] = False

            # Variable-length field: read length
            if field.is_variable:
                if lens_ptr < 0 or lens_ptr >= len(page):
                    return None

                len_byte = page[lens_ptr]
                lens_ptr -= 1

                needs_2_bytes = (field.max_length > 255 or
                                field.mysql_type in (
                                    MYSQL_TYPE_BLOB, MYSQL_TYPE_TINY_BLOB,
                                    MYSQL_TYPE_MEDIUM_BLOB, MYSQL_TYPE_LONG_BLOB,
                                    MYSQL_TYPE_JSON, MYSQL_TYPE_GEOMETRY,
                                ))

                if needs_2_bytes:
                    if len_byte & 0x80:
                        # 1xxxxxxx xxxxxxxx format
                        second_byte = page[lens_ptr]
                        lens_ptr -= 1
                        field_len = ((len_byte & 0x7F) << 8) | second_byte
                        # Check for external storage flag
                        is_external = bool(field_len & 0x4000)
                        field_len = field_len & 0x3FFF
                    else:
                        field_len = len_byte
                        is_external = False
                else:
                    field_len = len_byte
                    is_external = False

                current_offset += field_len
                if is_external:
                    field_offsets.append(current_offset | REC_OFFS_EXTERNAL)
                else:
                    field_offsets.append(current_offset)
            else:
                # Fixed-length field
                current_offset += field.fixed_length
                field_offsets.append(current_offset)

        # Parse field data
        record = ParsedRecord(
            page_offset=origin,
            deleted=deleted,
        )

        data_pos = origin  # Start of field data

        for i, field in enumerate(fields):
            if i >= len(field_offsets):
                break

            offset_val = field_offsets[i]

            if offset_val & REC_OFFS_SQL_NULL:
                record.field_values[field.name] = None
                record.null_fields.append(field.name)
                continue

            is_external = bool(offset_val & REC_OFFS_EXTERNAL)
            data_len = offset_val & 0x3FFF

            if data_pos + data_len > UNIV_PAGE_SIZE:
                break

            raw_data = page[data_pos:data_pos + data_len]

            if is_external:
                record.external_fields.append(field.name)
                # For external data, we store a marker
                record.field_values[field.name] = f'[EXTERNAL:{data_len}B]'
                record.field_raw[field.name] = raw_data
            else:
                value = parse_field_value(raw_data, field)
                record.field_values[field.name] = value
                record.field_raw[field.name] = raw_data

            data_pos += data_len

        # For clustered index: parse trx_id and roll_ptr after data fields
        if is_clustered and data_pos + 13 <= origin + 8000:
            # trx_id is 6 bytes
            if data_pos + 6 <= UNIV_PAGE_SIZE:
                record.trx_id = mach_read_from_6(page, data_pos) if data_pos + 6 <= UNIV_PAGE_SIZE else 0
                data_pos += 6
            # roll_ptr is 7 bytes
            if data_pos + 7 <= UNIV_PAGE_SIZE:
                record.roll_ptr = 0  # Simplified
                data_pos += 7

        return record

    except Exception as e:
        logger.debug(f"Error parsing compact record at offset {origin}: {e}")
        return None


def mach_read_from_6(page: bytes, offset: int) -> int:
    """Read a 6-byte big-endian unsigned integer."""
    if offset + 6 > len(page):
        return 0
    result = 0
    for i in range(6):
        result = (result << 8) | page[offset + i]
    return result


def parse_field_value(raw_data: bytes, field: FieldDefinition) -> Any:
    """Parse a field's raw bytes into a Python value."""
    if not raw_data:
        return None

    try:
        ft = field.field_type

        if ft == DATA_TINY:
            val = raw_data[0]
            return val if not field.is_unsigned else val  # Already unsigned byte

        elif ft == DATA_SHORT:
            val = struct.unpack('>h' if not field.is_unsigned else '>H', raw_data[:2])[0]
            return val

        elif ft == DATA_INT:
            val = struct.unpack('>i' if not field.is_unsigned else '>I', raw_data[:4])[0]
            return val

        elif ft == DATA_LONG:
            val = struct.unpack('>q' if not field.is_unsigned else '>Q', raw_data[:8])[0]
            return val

        elif ft == DATA_FLOAT:
            return struct.unpack('>f', raw_data[:4])[0]

        elif ft == DATA_DOUBLE:
            return struct.unpack('>d', raw_data[:8])[0]

        elif ft == DATA_DATE:
            return parse_mysql_date(raw_data[:3])

        elif ft == DATA_DATETIME:
            return parse_mysql_datetime(raw_data[:8])

        elif ft == DATA_TIMESTAMP:
            return parse_mysql_timestamp(raw_data[:4])

        elif ft == DATA_TIME:
            return parse_mysql_time(raw_data[:3])

        elif ft == DATA_YEAR:
            year = raw_data[0] + 1900 if raw_data[0] != 0 else 0
            return year

        elif ft == DATA_BIT:
            return parse_mysql_bit(raw_data, field.char_length)

        elif ft in (DATA_CHAR, DATA_VARCHAR):
            return raw_data.decode('utf-8', errors='replace').rstrip('\x00')

        elif ft in (DATA_BINARY, DATA_VARBINARY):
            return raw_data.hex()

        elif ft in (DATA_BLOB, DATA_TEXT):
            return raw_data.hex()  # Return hex for BLOB/TEXT

        elif ft == DATA_DECIMAL:
            return parse_mysql_decimal(raw_data, field)

        elif ft == DATA_JSON:
            try:
                # Try to parse JSON
                length = len(raw_data)
                if raw_data[0] == 0x00:
                    # Binary JSON format
                    return f'[JSON:{length}B]'
                return raw_data.decode('utf-8', errors='replace')
            except Exception:
                return f'[JSON:{len(raw_data)}B]'

        elif ft == DATA_GEOMETRY:
            return f'[GEOMETRY:{len(raw_data)}B]'

        elif ft in (DATA_ENUM, DATA_SET):
            return raw_data.decode('utf-8', errors='replace')

        else:
            return raw_data.decode('utf-8', errors='replace')

    except Exception as e:
        logger.debug(f"Error parsing field {field.name}: {e}")
        return raw_data.hex() if raw_data else None


def parse_mysql_date(data: bytes) -> str:
    """Parse MySQL DATE (3 bytes)."""
    if len(data) < 3:
        return None
    day = data[0]
    month = data[1]
    # Year is stored as a 2-byte big-endian value
    year = struct.unpack('>H', data[2:4])[0] if len(data) >= 4 else data[2]
    if year == 0 or month == 0 or day == 0:
        return '0000-00-00'
    return f'{year:04d}-{month:02d}-{day:02d}'


def parse_mysql_datetime(data: bytes) -> str:
    """Parse MySQL DATETIME (5 or 8 bytes)."""
    if len(data) < 5:
        return None
    if len(data) >= 8:
        # DATETIME with fractional seconds (8 bytes)
        date_part = data[:4]
        time_part = data[4:7]
        frac = data[7]
        year = struct.unpack('>H', date_part[:2])[0] if len(date_part) >= 2 else 0
        month = date_part[2] if len(date_part) > 2 else 0
        day = date_part[3] if len(date_part) > 3 else 0
        hour = time_part[0] if len(time_part) > 0 else 0
        minute = time_part[1] if len(time_part) > 1 else 0
        second = time_part[2] if len(time_part) > 2 else 0
        return f'{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}'
    else:
        # DATETIME without fractional seconds (5 bytes)
        year = struct.unpack('>H', b'\x00' + data[0:1])[0]
        month = data[1]
        day = data[2]
        hour = data[3]
        minute = data[4]
        return f'{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:00'


def parse_mysql_timestamp(data: bytes) -> str:
    """Parse MySQL TIMESTAMP (4 bytes, Unix timestamp)."""
    if len(data) < 4:
        return None
    ts = struct.unpack('>I', data[:4])[0]
    if ts == 0:
        return '0000-00-00 00:00:00'
    try:
        dt = datetime.utcfromtimestamp(ts)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (OSError, OverflowError, ValueError):
        return f'[TIMESTAMP:{ts}]'


def parse_mysql_time(data: bytes) -> str:
    """Parse MySQL TIME (3 bytes)."""
    if len(data) < 3:
        return None
    is_negative = bool(data[0] & 0x80)
    days = (data[0] & 0x7F)
    hours = data[1]
    minutes = data[2]
    total_hours = days * 24 + hours
    sign = '-' if is_negative else ''
    return f'{sign}{total_hours:02d}:{minutes:02d}:00'


def parse_mysql_bit(data: bytes, char_length: int) -> str:
    """Parse MySQL BIT type."""
    return int.from_bytes(data, byteorder='big')


def parse_mysql_decimal(data: bytes, field: FieldDefinition) -> str:
    """Parse MySQL DECIMAL type (binary representation)."""
    # Simplified decimal parsing
    try:
        precision = field.numeric_precision or 10
        scale = field.numeric_scale or 0
        return str(int.from_bytes(data, byteorder='big', signed=True))
    except Exception:
        return data.hex()
