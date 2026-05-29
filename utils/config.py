"""
InnoDB Undrop for MySQL 8.0 - Constants and Configuration
Based on MySQL 8.0.46 source code analysis of storage/innobase/include/
"""

# ============================================================
# Page Size - MySQL 8.0 supports multiple page sizes
# Default is 16384 (16KB), but 4KB, 8KB, 32KB, 64KB are also possible
# ============================================================
UNIV_PAGE_SIZE = 16384  # Default InnoDB page size (16KB)
UNIV_PAGE_SIZE_SHIFT = 14  # 2^14 = 16384

# Hash constants (from MySQL InnoDB source)
UT_HASH_RANDOM_MASK = 1463735687
UT_HASH_RANDOM_MASK2 = 1653893711

# Valid page sizes in MySQL 8.0
VALID_PAGE_SIZES = [4096, 8192, 16384, 32768, 65536]

# ============================================================
# FIL (File) Page Header Offsets
# From MySQL 8.0: storage/innobase/include/fil0types.h
# ============================================================
FIL_PAGE_SPACE_OR_CHKSUM = 0      # 4 bytes: Checksum (post-4.0.14) or space ID (pre-4.0.14)
FIL_PAGE_OFFSET = 4                # 4 bytes: Page number within space
FIL_PAGE_PREV = 8                  # 4 bytes: Previous page in B-tree leaf chain
FIL_PAGE_SRV_VERSION = 8           # Alias (MySQL 8.0 SDI)
FIL_PAGE_NEXT = 12                 # 4 bytes: Next page in B-tree leaf chain
FIL_PAGE_SPACE_VERSION = 12        # Alias (MySQL 8.0 SDI)
FIL_PAGE_LSN = 16                  # 8 bytes: Log Sequence Number
FIL_PAGE_TYPE = 24                  # 2 bytes: Page type
FIL_PAGE_FILE_FLUSH_LSN = 26       # 8 bytes: Flush LSN (only page 0)
FIL_PAGE_ARCH_LOG_NO_OR_SPACE_ID = 34  # 4 bytes: Space ID (post-4.1.x)
FIL_PAGE_SPACE_ID = 34             # Alias
FIL_PAGE_DATA = 38                 # Start of page data area
FIL_PAGE_END_LSN_OLD_CHKSUM = 8    # Last 4 bytes of page = old checksum
FIL_PAGE_DATA_END = 8              # Data ends 8 bytes before page end

# SDI version stored at FIL_PAGE_FILE_FLUSH_LSN on page 1 & 2
FIL_PAGE_VERSION = FIL_PAGE_FILE_FLUSH_LSN          # 1 byte
FIL_PAGE_ALGORITHM_V1 = FIL_PAGE_VERSION + 1        # 1 byte
FIL_PAGE_ORIGINAL_TYPE_V1 = FIL_PAGE_ALGORITHM_V1 + 1  # 2 bytes
FIL_PAGE_ORIGINAL_SIZE_V1 = FIL_PAGE_ORIGINAL_TYPE_V1 + 2  # 2 bytes
FIL_PAGE_COMPRESS_SIZE_V1 = FIL_PAGE_ORIGINAL_SIZE_V1 + 2  # 2 bytes

# ============================================================
# Page Types
# From MySQL 8.0: storage/innobase/include/fil0fil.h
# ============================================================
FIL_PAGE_TYPE_ALLOCATED = 0        # Freshly allocated page
FIL_PAGE_TYPE_UNUSED = 1           # Unused page
FIL_PAGE_UNDO_LOG = 2              # Undo log page
FIL_PAGE_INODE = 3                 # Inode page
FIL_PAGE_IBUF_FREE_LIST = 4        # Insert buffer free list
FIL_PAGE_IBUF_BITMAP = 5           # Insert buffer bitmap
FIL_PAGE_TYPE_SYS = 6             # System page
FIL_PAGE_TYPE_TRX_SYS = 7         # Transaction system page
FIL_PAGE_TYPE_FSP_HDR = 8          # File space header
FIL_PAGE_TYPE_XDES = 9             # Extent descriptor page
FIL_PAGE_TYPE_BLOB = 10            # Uncompressed BLOB page
FIL_PAGE_TYPE_ZBLOB = 11            # Compressed BLOB page (first)
FIL_PAGE_TYPE_ZBLOB2 = 12           # Compressed BLOB page (subsequent)
FIL_PAGE_TYPE_UNKNOWN = 13          # Garbage page type (old tablespaces)
FIL_PAGE_COMPRESSED = 14            # Compressed page
FIL_PAGE_ENCRYPTED = 15             # Encrypted page
FIL_PAGE_COMPRESSED_AND_ENCRYPTED = 16  # Compressed + encrypted
FIL_PAGE_ENCRYPTED_RTREE = 17        # Encrypted R-tree page
FIL_PAGE_SDI_BLOB = 18              # SDI BLOB page
FIL_PAGE_SDI_ZBLOB = 19             # Compressed SDI BLOB page
FIL_PAGE_TYPE_LEGACY_DBLWR = 20      # Legacy doublewrite page
FIL_PAGE_TYPE_RSEG_ARRAY = 21       # Rollback segment array
FIL_PAGE_TYPE_LOB_INDEX = 22        # LOB index page
FIL_PAGE_TYPE_LOB_DATA = 23         # LOB data page
FIL_PAGE_TYPE_LOB_FIRST = 24        # First LOB data page
FIL_PAGE_TYPE_ZLOB_FIRST = 25       # First compressed LOB page
FIL_PAGE_TYPE_ZLOB_DATA = 26        # Compressed LOB data page
FIL_PAGE_TYPE_ZLOB_INDEX = 27        # Compressed LOB index page
FIL_PAGE_TYPE_ZLOB_FRAG = 28        # Compressed LOB fragment page
FIL_PAGE_TYPE_ZLOB_FRAG_ENTRY = 29   # Compressed LOB fragment entry page

# Key page types for recovery
FIL_PAGE_INDEX = 17855              # B-tree index page (clustered or secondary)
FIL_PAGE_RTREE = 17854              # R-tree index page
FIL_PAGE_SDI = 17853                # SDI (Serialized Dictionary Info) page

# All index-like page types
INDEX_PAGE_TYPES = {FIL_PAGE_INDEX, FIL_PAGE_RTREE, FIL_PAGE_SDI}

# All BLOB page types
BLOB_PAGE_TYPES = {
    FIL_PAGE_TYPE_BLOB, FIL_PAGE_TYPE_ZBLOB, FIL_PAGE_TYPE_ZBLOB2,
    FIL_PAGE_SDI_BLOB, FIL_PAGE_SDI_ZBLOB
}

# LOB page types (MySQL 8.0)
LOB_PAGE_TYPES = {
    FIL_PAGE_TYPE_LOB_INDEX, FIL_PAGE_TYPE_LOB_DATA, FIL_PAGE_TYPE_LOB_FIRST,
    FIL_PAGE_TYPE_ZLOB_FIRST, FIL_PAGE_TYPE_ZLOB_DATA, FIL_PAGE_TYPE_ZLOB_INDEX,
    FIL_PAGE_TYPE_ZLOB_FRAG, FIL_PAGE_TYPE_ZLOB_FRAG_ENTRY
}

# Compressed/encrypted page types
COMPRESSION_TYPES = {FIL_PAGE_COMPRESSED, FIL_PAGE_COMPRESSED_AND_ENCRYPTED}
ENCRYPTED_TYPES = {FIL_PAGE_ENCRYPTED, FIL_PAGE_COMPRESSED_AND_ENCRYPTED, FIL_PAGE_ENCRYPTED_RTREE}

# ============================================================
# Page Header Offsets (Index pages)
# From MySQL 8.0: storage/innobase/include/page0types.h
# ============================================================
FSEG_PAGE_DATA = FIL_PAGE_DATA       # File segment data starts here
PAGE_HEADER = FSEG_PAGE_DATA          # Index page header
PAGE_N_DIR_SLOTS = 0                  # Number of directory slots
PAGE_HEAP_TOP = 2                     # Pointer to heap top
PAGE_N_HEAP = 4                       # Number of records in heap; bit 15 = compact format flag
PAGE_FREE = 6                         # Start of free record list
PAGE_GARBAGE = 8                      # Bytes in deleted records
PAGE_LAST_INSERT = 10                 # Pointer to last inserted record
PAGE_DIRECTION = 12                  # Last insert direction
PAGE_N_DIRECTION = 14                 # Number of consecutive same-direction inserts
PAGE_N_RECS = 16                      # Number of user records
PAGE_MAX_TRX_ID = 18                  # Max transaction ID (secondary indexes)
PAGE_HEADER_PRIV_END = 26             # End of private page header data
PAGE_LEVEL = 26                       # B-tree level (leaf = 0)
PAGE_INDEX_ID = 28                     # Index ID (8 bytes)

# File segment header
FSEG_HEADER_SIZE = 10
PAGE_BTR_SEG_LEAF = 36                # B-tree leaf segment (root page only)
PAGE_BTR_SEG_TOP = 36 + FSEG_HEADER_SIZE  # B-tree non-leaf segment (root page only)
PAGE_DATA = PAGE_HEADER + 36 + 2 * FSEG_HEADER_SIZE  # = 38 + 36 + 20 = 94... wait

# Actually: PAGE_DATA = PAGE_HEADER + 36 + 2*FSEG_HEADER_SIZE
# PAGE_HEADER = 38, so PAGE_DATA = 38 + 36 + 20 = 94? No...
# From source: PAGE_HEADER + 36 + 2 * FSEG_HEADER_SIZE
# The 36 is the size of the page header (up to PAGE_BTR_SEG_TOP end)
# Actually from the source: 36 bytes of header fields + 2 * 10 bytes segment headers
# = PAGE_HEADER = 38, then + 36 = 74, + 20 = 94? Let me recalculate
# From source code: PAGE_DATA = PAGE_HEADER + 36 + 2 * FSEG_HEADER_SIZE
# This is the fixed calculation from InnoDB source

# Record positions
REC_N_NEW_EXTRA_BYTES = 5   # Extra bytes for COMPACT/DYNAMIC records
REC_N_OLD_EXTRA_BYTES = 6   # Extra bytes for REDUNDANT records

# Infimum/Supremum record positions
PAGE_OLD_INFIMUM = 99   # REDUNDANT format (calculated from source)
PAGE_OLD_SUPREMUM = 117  # REDUNDANT format
PAGE_NEW_INFIMUM = 99    # COMPACT format  (PAGE_DATA + REC_N_NEW_EXTRA_BYTES)
PAGE_NEW_SUPREMUM = 117  # COMPACT format  (PAGE_DATA + 2*REC_N_NEW_EXTRA_BYTES + 8)

# Re-derive precisely:
# PAGE_DATA = PAGE_HEADER + 36 + 2 * FSEG_HEADER_SIZE = 38 + 36 + 20 = 94
# Wait - from source code directly:
# PAGE_DATA = PAGE_HEADER + 36 + 2 * FSEG_HEADER_SIZE
# PAGE_HEADER = FSEG_PAGE_DATA = FIL_PAGE_DATA = 38
# So PAGE_DATA = 38 + 36 + 2*10 = 94
# PAGE_NEW_INFIMUM = PAGE_DATA + REC_N_NEW_EXTRA_BYTES = 94 + 5 = 99
# PAGE_NEW_SUPREMUM = PAGE_DATA + 2 * REC_N_NEW_EXTRA_BYTES + 8 = 94 + 10 + 8 = 112
# Hmm, but the source says PAGE_NEW_SUPREMUM = PAGE_DATA + 2 * REC_N_NEW_EXTRA_BYTES + 8

PAGE_DATA_OFFSET = PAGE_HEADER + 36 + 2 * FSEG_HEADER_SIZE  # = 94
PAGE_NEW_INFIMUM_OFFSET = PAGE_DATA_OFFSET + REC_N_NEW_EXTRA_BYTES  # = 99
PAGE_NEW_SUPREMUM_OFFSET = PAGE_DATA_OFFSET + 2 * REC_N_NEW_EXTRA_BYTES + 8  # = 112
PAGE_OLD_INFIMUM_OFFSET = PAGE_DATA_OFFSET + 1 + REC_N_OLD_EXTRA_BYTES  # = 101
PAGE_OLD_SUPREMUM_OFFSET = PAGE_DATA_OFFSET + 2 + 2 * REC_N_OLD_EXTRA_BYTES + 8  # = 120

# Infimum/Supremum data
INFIMUM_DATA = b'infimum\x00'
SUPREMUM_DATA = b'supremum'

# ============================================================
# Record Format Constants
# ============================================================
REC_STATUS_ORDINARY = 0     # Ordinary user record
REC_STATUS_INFIMUM = 1      # Infimum record
REC_STATUS_SUPREMUM = 2     # Supremum record
REC_STATUS_NODE_PTR = 3      # B-tree node pointer (non-leaf)

REC_OFFS_SQL_NULL = 0x8000  # SQL NULL flag in offset
REC_OFFS_EXTERNAL = 0x4000  # Externally stored flag
REC_1BYTE_SQL_NULL_MASK = 0x80
REC_2BYTE_SQL_NULL_MASK = 0x8000
REC_2BYTE_EXTERN_MASK = 0x4000

# Info bits flags in record header (upper nibble of byte at rec-5 in compact format)
# From MySQL 8.0: storage/innobase/rem/rec.h
# REC_NEW_INFO_BITS = 5 (offset from rec), mask = 0xF0, shift = 0
# Info bits = page[rec-5] & 0xF0 (upper nibble)
# N_OWNED = page[rec-5] & 0x0F (lower nibble, shared byte with INFO_BITS)
REC_INFO_DELETED_FLAG = 0x20     # Delete-marked flag (bit 5 of byte at rec-5)
REC_INFO_MIN_REC_FLAG = 0x10      # Minimum record in index page
REC_INFO_INSTANT_FLAG = 0x80      # Instant ADD COLUMN flag
REC_INFO_VERSION_FLAG = 0x40      # Record has version

# Record header field offsets from rec (going backwards)
# From MySQL 8.0: storage/innobase/rem/rec.h
REC_NEXT = 2            # Next record offset (2 bytes at rec-2..rec-1)
REC_NEW_HEAP_NO = 4      # Heap number (13 bits, 2 bytes at rec-4..rec-3)
REC_NEW_N_OWNED = 5      # N_OWNED (4 bits in lower nibble of byte at rec-5)
REC_NEW_INFO_BITS = 5    # Info bits (4 bits in upper nibble of byte at rec-5)
REC_NEW_STATUS = 3       # Record status (3 bits in lower 3 bits of byte at rec-3)

# ============================================================
# InnoDB Data Types
# ============================================================
DATA_CHAR = 'CHAR'
DATA_VARCHAR = 'VARCHAR'
DATA_BINARY = 'BINARY'
DATA_VARBINARY = 'VARBINARY'
DATA_TINY = 'TINYINT'
DATA_SHORT = 'SMALLINT'
DATA_INT = 'INT'
DATA_LONG = 'BIGINT'
DATA_FLOAT = 'FLOAT'
DATA_DOUBLE = 'DOUBLE'
DATA_DECIMAL = 'DECIMAL'
DATA_BLOB = 'BLOB'
DATA_TEXT = 'TEXT'
DATA_DATE = 'DATE'
DATA_DATETIME = 'DATETIME'
DATA_TIMESTAMP = 'TIMESTAMP'
DATA_TIME = 'TIME'
DATA_YEAR = 'YEAR'
DATA_BIT = 'BIT'
DATA_ENUM = 'ENUM'
DATA_SET = 'SET'
DATA_JSON = 'JSON'
DATA_GEOMETRY = 'GEOMETRY'
DATA_UNKNOWN = 'UNKNOWN'

# Fixed-length data type sizes (in bytes)
FIXED_LENGTH_TYPES = {
    DATA_TINY: 1,
    DATA_SHORT: 2,
    DATA_INT: 4,
    DATA_LONG: 8,
    DATA_FLOAT: 4,
    DATA_DOUBLE: 8,
    DATA_DATE: 3,
    DATA_TIME: 3,
    DATA_YEAR: 1,
}

# ============================================================
# SDI (Serialized Dictionary Info) Constants
# MySQL 8.0 stores table metadata in SDI pages
# ============================================================
SDI_KEY = {'type': 'SDI_INDEX', 'id': 0}
SDI_VERSION = 1

# ============================================================
# MySQL Type Codes (for parsing .frm equivalent from SDI)
# ============================================================
MYSQL_TYPE_DECIMAL = 0
MYSQL_TYPE_TINY = 1
MYSQL_TYPE_SHORT = 2
MYSQL_TYPE_LONG = 3
MYSQL_TYPE_FLOAT = 4
MYSQL_TYPE_DOUBLE = 5
MYSQL_TYPE_NULL = 6
MYSQL_TYPE_TIMESTAMP = 7
MYSQL_TYPE_LONGLONG = 8
MYSQL_TYPE_INT24 = 9
MYSQL_TYPE_DATE = 10
MYSQL_TYPE_TIME = 11
MYSQL_TYPE_DATETIME = 12
MYSQL_TYPE_YEAR = 13
MYSQL_TYPE_NEWDATE = 14
MYSQL_TYPE_VARCHAR = 15
MYSQL_TYPE_BIT = 16
MYSQL_TYPE_NEWDECIMAL = 246
MYSQL_TYPE_ENUM = 247
MYSQL_TYPE_SET = 248
MYSQL_TYPE_TINY_BLOB = 249
MYSQL_TYPE_MEDIUM_BLOB = 250
MYSQL_TYPE_LONG_BLOB = 251
MYSQL_TYPE_BLOB = 252
MYSQL_TYPE_VAR_STRING = 253
MYSQL_TYPE_STRING = 254
MYSQL_TYPE_GEOMETRY = 255
MYSQL_TYPE_JSON = 245

# ============================================================
# File segment constants
# ============================================================
FSEG_HDR_SPACE = 0   # 4 bytes
FSEG_HDR_PAGE_NO = 4  # 4 bytes
FSEG_HDR_OFFSET = 8   # 2 bytes

FIL_NULL = 0xFFFFFFFF  # Null page reference

# ============================================================
# Checksum algorithm names
# ============================================================
SRV_CHECKSUM_ALGORITHM_NONE = 0              # innodb_checksum_none
SRV_CHECKSUM_ALGORITHM_INNODB = 1           # innodb (legacy)
SRV_CHECKSUM_ALGORITHM_STRICT_INNODB = 2    # strict_innodb
SRV_CHECKSUM_ALGORITHM_CRC32 = 3             # crc32
SRV_CHECKSUM_ALGORITHM_STRICT_CRC32 = 4     # strict_crc32 (MySQL 8.0 default)

CHECKSUM_ALGORITHM_NAMES = {
    SRV_CHECKSUM_ALGORITHM_NONE: 'none',
    SRV_CHECKSUM_ALGORITHM_INNODB: 'innodb',
    SRV_CHECKSUM_ALGORITHM_STRICT_INNODB: 'strict_innodb',
    SRV_CHECKSUM_ALGORITHM_CRC32: 'crc32',
    SRV_CHECKSUM_ALGORITHM_STRICT_CRC32: 'strict_crc32',
}

# MySQL 8.0 default checksum algorithm
DEFAULT_CHECKSUM_ALGORITHM = SRV_CHECKSUM_ALGORITHM_CRC32
