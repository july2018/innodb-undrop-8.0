# InnoDB Undrop for MySQL 8.0

A Python-based recovery tool for MySQL 8.0 InnoDB tables, inspired by [twindb/undrop-for-innodb](https://github.com/twindb/undrop-for-innodb).

## Features

- **Recover dropped tables**: Scan InnoDB data files to find pages belonging to dropped tables and reconstruct data
- **Recover deleted rows**: Parse InnoDB pages to find logically deleted rows (rows marked with delete flag)
- **MySQL 8.0 compatible**: Supports MySQL 8.0 InnoDB page format including DYNAMIC/COMPRESSED row formats, SDI pages, and new checksum algorithms (crc32, strict_innodb, strict_crc32, none)
- **No backup required**: Works directly on raw InnoDB data files (.ibd, ibdata1)
- **Multiple output formats**: Export recovered data as SQL INSERT statements or CSV files

## Supported Scenarios

- `DROP TABLE` recovery (no backup, no binlog)
- `DELETE FROM` recovery (no binlog enabled)
- `TRUNCATE TABLE` recovery
- Corrupted InnoDB tablespace data extraction
- File system level recovery after accidental deletion

## Requirements

- Python 3.8+
- No MySQL server required (works offline on raw files)

## Quick Start

```bash
# Recover a dropped table
python innodb_undrop.py --datadir /var/lib/mysql --database mydb --table mytable --output recovered_data.sql

# Recover deleted rows from a table
python innodb_undrop.py --datadir /var/lib/mysql --database mydb --table mytable --deleted-only --output deleted_rows.sql

# Recover with CREATE TABLE definition
python innodb_undrop.py --datadir /var/lib/mysql --database mydb --table mytable --create-table "CREATE TABLE mytable (id INT PRIMARY KEY, name VARCHAR(100))" --output recovered.sql

# Scan all tables in a database
python innodb_undrop.py --datadir /var/lib/mysql --database mydb --scan-all --output recovered/
```

## How It Works

1. **Page Scanner**: Scans raw InnoDB files (.ibd, ibdata1) for valid data pages
2. **Page Validator**: Validates pages using MySQL 8.0 checksum algorithms (crc32, innodb, none)
3. **Record Parser**: Parses COMPACT/DYNAMIC row format records from leaf pages
4. **Table Matcher**: Matches recovered records to table structure
5. **Data Exporter**: Generates SQL or CSV output with recovered data

### Key MySQL 8.0 Differences Handled

- **SDI (Serialized Dictionary Information)**: MySQL 8.0 stores table metadata in SDI pages (type 17853). The tool extracts table structure from SDI when no CREATE TABLE is provided.
- **New page types**: Supports all MySQL 8.0 page types including LOB_INDEX (22), LOB_DATA (23), ZLOB types (25-29)
- **Checksum algorithms**: Supports crc32, strict_crc32, strict_innodb, and none algorithms
- **DYNAMIC row format**: Full support for off-page storage (LOB) for large columns
- **Encrypted pages**: Detects encrypted tablespaces and warns the user

## Architecture

```
innodb_undrop/
  __init__.py
  innodb_undrop.py      # Main CLI entry point
  parser/
    __init__.py
    page_scanner.py     # Scan files for InnoDB pages
    page_parser.py       # Parse individual page structure
    record_parser.py     # Parse records from pages
    checksum.py          # MySQL 8.0 checksum algorithms
    sdi_parser.py        # Parse SDI (Serialized Dictionary Info) pages
    ibd_reader.py        # Read .ibd file structure
  recovery/
    __init__.py
    table_recovery.py    # Recover dropped tables
    row_recovery.py      # Recover deleted rows
    data_dict.py          # Data dictionary recovery
  export/
    __init__.py
    sql_exporter.py       # Export as SQL INSERT statements
    csv_exporter.py       # Export as CSV files
  utils/
    __init__.py
    config.py             # Configuration constants
    logging_setup.py     # Logging configuration
```


