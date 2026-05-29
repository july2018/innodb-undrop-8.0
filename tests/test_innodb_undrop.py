"""
Tests for InnoDB Undrop for MySQL 8.0
"""

import unittest
import struct
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.config import *
from parser.checksum import (
    mach_read_from_2, mach_read_from_4, mach_read_from_8,
    buf_calc_page_old_checksum, buf_calc_page_new_checksum,
    buf_calc_page_crc32, validate_checksum,
    ut_fold_binary, ut_fold_ulint_pair,
)
from parser.page_parser import (
    parse_film_header, is_compact_page, validate_infimum_supremum,
    is_valid_index_page, get_record_pointers,
)
from parser.record_parser import (
    parse_create_table, FieldDefinition,
    map_mysql_type, map_field_type, get_type_fixed_length,
    parse_field_value, parse_mysql_date, parse_mysql_datetime,
    parse_mysql_time, parse_mysql_bit,
)
from parser.sdi_parser import (
    is_sdi_page, find_json_start, try_parse_sdi_json,
    parse_sdi_to_table_info,
)


class TestChecksumFunctions(unittest.TestCase):
    """Test checksum calculation functions."""

    def test_mach_read_from_4(self):
        # Big-endian 4-byte read
        data = b'\x00\x00\x00\x01'
        self.assertEqual(mach_read_from_4(data, 0), 1)

        data = b'\xFF\xFF\xFF\xFF'
        self.assertEqual(mach_read_from_4(data, 0), 0xFFFFFFFF)

        data = b'\x12\x34\x56\x78'
        self.assertEqual(mach_read_from_4(data, 0), 0x12345678)

    def test_mach_read_from_2(self):
        data = b'\x00\x01'
        self.assertEqual(mach_read_from_2(data, 0), 1)

        data = b'\xFF\xFF'
        self.assertEqual(mach_read_from_2(data, 0), 0xFFFF)

        data = b'\x45\xD3'
        self.assertEqual(mach_read_from_2(data, 0), 0x45D3)

    def test_mach_read_from_8(self):
        data = b'\x00\x00\x00\x00\x00\x00\x00\x01'
        self.assertEqual(mach_read_from_8(data, 0), 1)

    def test_ut_fold_ulint_pair(self):
        result = ut_fold_ulint_pair(1, 2)
        self.assertIsInstance(result, int)
        # Verify deterministic
        self.assertEqual(ut_fold_ulint_pair(1, 2), ut_fold_ulint_pair(1, 2))

    def test_ut_fold_binary(self):
        fold = ut_fold_binary(b'\x00' * 100)
        self.assertIsInstance(fold, int)

    def test_buf_calc_page_crc32(self):
        # Create a page-like buffer
        page = bytearray(UNIV_PAGE_SIZE)
        # Set FIL_PAGE_TYPE to FIL_PAGE_INDEX
        page[FIL_PAGE_TYPE] = 0x45  # Low byte of 17855
        page[FIL_PAGE_TYPE + 1] = 0xBF  # High byte of 17855

        crc = buf_calc_page_crc32(bytes(page))
        self.assertIsInstance(crc, int)
        self.assertGreater(crc, 0)

    def test_buf_calc_page_new_checksum(self):
        page = bytearray(UNIV_PAGE_SIZE)
        checksum = buf_calc_page_new_checksum(bytes(page))
        self.assertIsInstance(checksum, int)

    def test_buf_calc_page_old_checksum(self):
        page = bytearray(UNIV_PAGE_SIZE)
        checksum = buf_calc_page_old_checksum(bytes(page))
        self.assertIsInstance(checksum, int)

    def test_validate_checksum_empty_page(self):
        page = b'\x00' * UNIV_PAGE_SIZE
        valid, algo = validate_checksum(page)
        self.assertFalse(valid)

    def test_validate_checksum_with_crc32(self):
        """Test that validate_checksum can identify CRC32 checksums."""
        page = bytearray(UNIV_PAGE_SIZE)
        # Set FIL_PAGE_TYPE to FIL_PAGE_INDEX
        struct.pack_into('>H', page, FIL_PAGE_TYPE, FIL_PAGE_INDEX)
        # Set some page data
        page[FIL_PAGE_OFFSET:FIL_PAGE_OFFSET + 4] = struct.pack('>I', 1)

        # Calculate and store CRC32
        crc = buf_calc_page_crc32(bytes(page))
        struct.pack_into('>I', page, FIL_PAGE_SPACE_OR_CHKSUM, crc)

        valid, algo = validate_checksum(bytes(page))
        self.assertTrue(valid)


class TestPageParser(unittest.TestCase):
    """Test InnoDB page parsing."""

    def test_parse_film_header_valid_page(self):
        page = bytearray(UNIV_PAGE_SIZE)
        # Set FIL page header fields
        struct.pack_into('>H', page, FIL_PAGE_TYPE, FIL_PAGE_INDEX)
        struct.pack_into('>I', page, FIL_PAGE_OFFSET, 5)
        struct.pack_into('>I', page, FIL_PAGE_PREV, 0xFFFFFFFF)
        struct.pack_into('>I', page, FIL_PAGE_NEXT, 6)

        header = parse_film_header(bytes(page))
        self.assertEqual(header['page_type'], FIL_PAGE_INDEX)
        self.assertEqual(header['page_no'], 5)
        self.assertEqual(header['prev_page'], 0xFFFFFFFF)
        self.assertEqual(header['next_page'], 6)

    def test_is_compact_page(self):
        page = bytearray(UNIV_PAGE_SIZE)
        # Set compact format flag in PAGE_N_HEAP
        struct.pack_into('>I', page, PAGE_HEADER + PAGE_N_HEAP, 0x80000005)
        self.assertTrue(is_compact_page(bytes(page)))

        # Set redundant format
        struct.pack_into('>I', page, PAGE_HEADER + PAGE_N_HEAP, 0x00000005)
        self.assertFalse(is_compact_page(bytes(page)))

    def test_validate_infimum_supremum(self):
        page = bytearray(UNIV_PAGE_SIZE)
        # Set compact format
        struct.pack_into('>I', page, PAGE_HEADER + PAGE_N_HEAP, 0x80000005)
        # Place infimum
        inf_offset = PAGE_NEW_INFIMUM_OFFSET  # 99
        page[inf_offset:inf_offset + 8] = INFIMUM_DATA
        # Place supremum
        sup_offset = PAGE_NEW_SUPREMUM_OFFSET  # 112
        page[sup_offset:sup_offset + 8] = SUPREMUM_DATA

        self.assertTrue(validate_infimum_supremum(bytes(page)))

    def test_validate_infimum_supremum_invalid(self):
        page = bytearray(UNIV_PAGE_SIZE)
        struct.pack_into('>I', page, PAGE_HEADER + PAGE_N_HEAP, 0x80000005)
        # Place wrong infimum
        page[99:107] = b'xxxxxxx'
        self.assertFalse(validate_infimum_supremum(bytes(page)))


class TestRecordParser(unittest.TestCase):
    """Test record and field parsing."""

    def test_parse_create_table_simple(self):
        sql = """CREATE TABLE test (
            id INT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            age TINYINT UNSIGNED,
            created_at DATETIME
        ) ENGINE=InnoDB;"""

        fields = parse_create_table(sql)
        self.assertEqual(len(fields), 4)
        self.assertEqual(fields[0].name, 'id')
        self.assertEqual(fields[0].field_type, DATA_INT)
        self.assertTrue(fields[0].is_primary_key)

        self.assertEqual(fields[1].name, 'name')
        self.assertEqual(fields[1].field_type, DATA_VARCHAR)
        self.assertTrue(fields[1].is_variable)
        self.assertEqual(fields[1].max_length, 100)
        self.assertFalse(fields[1].is_nullable)

        self.assertEqual(fields[2].name, 'age')
        self.assertTrue(fields[2].is_unsigned)

    def test_parse_create_table_with_blob(self):
        sql = """CREATE TABLE test (
            id INT PRIMARY KEY AUTO_INCREMENT,
            data BLOB,
            content TEXT,
            price DECIMAL(10,2)
        ) ENGINE=InnoDB;"""

        fields = parse_create_table(sql)
        self.assertEqual(len(fields), 4)
        self.assertEqual(fields[1].field_type, DATA_BLOB)
        self.assertTrue(fields[1].is_variable)
        self.assertEqual(fields[3].field_type, DATA_DECIMAL)
        self.assertEqual(fields[3].numeric_precision, 10)
        self.assertEqual(fields[3].numeric_scale, 2)

    def test_parse_mysql_date(self):
        # MySQL DATE: 3 bytes - day(1) + month(1) + year(1)
        # Year 2024 = 0x07E8, stored as 2 bytes big-endian
        data = bytes([15, 1, 0x07, 0xE8])  # 2024-01-15
        result = parse_mysql_date(data)
        self.assertIsNotNone(result)
        self.assertEqual(result, '2024-01-15')

    def test_parse_mysql_time(self):
        data = bytes([0, 10, 30])  # 10:30:00
        result = parse_mysql_time(data)
        self.assertIsNotNone(result)
        self.assertIn('10:30', result)

    def test_parse_mysql_bit(self):
        data = bytes([0xFF, 0x0F])  # 16 bits
        result = parse_mysql_bit(data, 16)
        self.assertIsInstance(result, int)
        self.assertEqual(result, 0xFF0F)

    def test_map_mysql_type(self):
        self.assertEqual(map_mysql_type('INT'), MYSQL_TYPE_LONG)
        self.assertEqual(map_mysql_type('VARCHAR'), MYSQL_TYPE_VARCHAR)
        self.assertEqual(map_mysql_type('BIGINT'), MYSQL_TYPE_LONGLONG)
        self.assertEqual(map_mysql_type('DATETIME'), MYSQL_TYPE_DATETIME)

    def test_map_field_type(self):
        self.assertEqual(map_field_type('INT'), DATA_INT)
        self.assertEqual(map_field_type('VARCHAR'), DATA_VARCHAR)
        self.assertEqual(map_field_type('BLOB'), DATA_BLOB)
        self.assertEqual(map_field_type('JSON'), DATA_JSON)


class TestSDIParser(unittest.TestCase):
    """Test SDI parsing functions."""

    def test_find_json_start(self):
        data = b'random data {"key": "value"} more data'
        start = find_json_start(data)
        self.assertEqual(start, data.index(b'{'))

    def test_find_json_start_not_found(self):
        data = b'no json here'
        start = find_json_start(data)
        self.assertEqual(start, -1)

    def test_try_parse_sdi_json(self):
        valid_json = b'{"mysqld_version_id": 80046, "dd_object": {}}'
        result = try_parse_sdi_json(valid_json)
        self.assertIsNotNone(result)

    def test_is_sdi_page(self):
        page = bytearray(UNIV_PAGE_SIZE)
        struct.pack_into('>H', page, FIL_PAGE_TYPE, FIL_PAGE_SDI)
        self.assertTrue(is_sdi_page(bytes(page)))

        struct.pack_into('>H', page, FIL_PAGE_TYPE, FIL_PAGE_INDEX)
        self.assertFalse(is_sdi_page(bytes(page)))


class TestPageTypeConstants(unittest.TestCase):
    """Verify that page type constants match MySQL 8.0 source."""

    def test_index_page_type(self):
        self.assertEqual(FIL_PAGE_INDEX, 17855)

    def test_sdi_page_type(self):
        self.assertEqual(FIL_PAGE_SDI, 17853)

    def test_rtree_page_type(self):
        self.assertEqual(FIL_PAGE_RTREE, 17854)

    def test_lob_page_types(self):
        self.assertEqual(FIL_PAGE_TYPE_LOB_INDEX, 22)
        self.assertEqual(FIL_PAGE_TYPE_LOB_DATA, 23)
        self.assertEqual(FIL_PAGE_TYPE_LOB_FIRST, 24)

    def test_zlob_page_types(self):
        self.assertEqual(FIL_PAGE_TYPE_ZLOB_FIRST, 25)
        self.assertEqual(FIL_PAGE_TYPE_ZLOB_DATA, 26)
        self.assertEqual(FIL_PAGE_TYPE_ZLOB_INDEX, 27)
        self.assertEqual(FIL_PAGE_TYPE_ZLOB_FRAG, 28)
        self.assertEqual(FIL_PAGE_TYPE_ZLOB_FRAG_ENTRY, 29)

    def test_compressed_encrypted_types(self):
        self.assertEqual(FIL_PAGE_COMPRESSED, 14)
        self.assertEqual(FIL_PAGE_ENCRYPTED, 15)
        self.assertEqual(FIL_PAGE_COMPRESSED_AND_ENCRYPTED, 16)

    def test_page_header_offsets(self):
        self.assertEqual(PAGE_N_DIR_SLOTS, 0)
        self.assertEqual(PAGE_HEAP_TOP, 2)
        self.assertEqual(PAGE_N_HEAP, 4)
        self.assertEqual(PAGE_LEVEL, 26)
        self.assertEqual(PAGE_INDEX_ID, 28)

    def test_fil_header_offsets(self):
        self.assertEqual(FIL_PAGE_SPACE_OR_CHKSUM, 0)
        self.assertEqual(FIL_PAGE_OFFSET, 4)
        self.assertEqual(FIL_PAGE_PREV, 8)
        self.assertEqual(FIL_PAGE_NEXT, 12)
        self.assertEqual(FIL_PAGE_LSN, 16)
        self.assertEqual(FIL_PAGE_TYPE, 24)
        self.assertEqual(FIL_PAGE_DATA, 38)

    def test_record_format_constants(self):
        self.assertEqual(REC_N_NEW_EXTRA_BYTES, 5)
        self.assertEqual(REC_N_OLD_EXTRA_BYTES, 6)

    def test_page_size(self):
        self.assertEqual(UNIV_PAGE_SIZE, 16384)


if __name__ == '__main__':
    unittest.main()
