#!/usr/bin/env python3
"""
InnoDB Undrop for MySQL 8.0
============================
A recovery tool for MySQL 8.0 InnoDB tables.

Recovers:
- Dropped tables (DROP TABLE without backup/binlog)
- Deleted rows (DELETE FROM without binlog)
- Truncated table data
- Data from corrupted InnoDB tablespaces

Usage:
    python innodb_undrop.py --datadir /var/lib/mysql --database mydb --table mytable [options]
"""

import os
import sys
import argparse
import logging

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recovery.table_recovery import (
    recover_dropped_table,
    recover_deleted_rows,
    scan_database_for_recoverable_tables,
    RecoveryResult,
)
from export.sql_exporter import export_to_sql, export_to_csv


def setup_logging(verbose: bool = False, debug: bool = False):
    """Configure logging."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        level=level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )


def cmd_recover(args):
    """Main recovery command."""
    logger = logging.getLogger(__name__)
    logger.info("=" * 60)
    logger.info("InnoDB Undrop for MySQL 8.0")
    logger.info("=" * 60)

    # Validate arguments
    if not args.datadir:
        logger.error("--datadir is required")
        return 1

    if not os.path.isdir(args.datadir):
        logger.error(f"Data directory does not exist: {args.datadir}")
        return 1

    if not args.database:
        logger.error("--database is required")
        return 1

    if not args.table:
        logger.error("--table is required")
        return 1

    # Determine output path
    output = args.output
    if not output:
        output = f"{args.database}_{args.table}_recovered.sql"

    logger.info(f"Recovery target: {args.database}.{args.table}")
    logger.info(f"Data directory: {args.datadir}")
    logger.info(f"Output file: {output}")

    # Determine recovery mode
    if args.deleted_only:
        logger.info("Mode: Recover deleted rows only")
        result = recover_deleted_rows(
            datadir=args.datadir,
            database=args.database,
            table=args.table,
            create_table=args.create_table,
            checksum_algo=args.checksum_algo,
        )
    else:
        logger.info("Mode: Recover all data (including deleted)")
        result = recover_dropped_table(
            datadir=args.datadir,
            database=args.database,
            table=args.table,
            create_table=args.create_table,
            checksum_algo=args.checksum_algo,
            recover_deleted_only=False,
        )

    # Export results
    if output.endswith('.csv'):
        export_to_csv(result, output, include_deleted=True)
    else:
        export_to_sql(
            result, output,
            include_deleted=not args.active_only,
            separate_deleted=True,
        )

    # Print summary
    print_summary(result)

    return 0 if result.records_recovered > 0 else 1


def cmd_scan(args):
    """Scan a database for recoverable tables."""
    logger = logging.getLogger(__name__)

    if not args.datadir or not args.database:
        logger.error("--datadir and --database are required for scan")
        return 1

    logger.info(f"Scanning database: {args.database}")
    tables = scan_database_for_recoverable_tables(args.datadir, args.database)

    if not tables:
        print(f"\nNo recoverable tables found in database '{args.database}'")
        return 1

    print(f"\n{'=' * 60}")
    print(f"Recoverable tables in database '{args.database}':")
    print(f"{'=' * 60}")

    for table_name, info in sorted(tables.items()):
        print(f"\n  Table: {table_name}")
        print(f"    Source: {info.get('ibd_path', 'unknown')}")
        if info.get('in_ibdata'):
            print(f"    NOTE: Found in ibdata1 (table may have been dropped)")
        if info.get('metadata'):
            meta = info['metadata']
            n_cols = len(meta.get('columns', []))
            create = meta.get('create_table', '')
            if create:
                # Print truncated CREATE TABLE
                for line in create.split('\n')[:5]:
                    print(f"    {line}")
                if len(create.split('\n')) > 5:
                    print(f"    ...")
            print(f"    Columns: {n_cols}")

    print(f"\nTotal: {len(tables)} recoverable tables found")
    return 0


def print_summary(result: RecoveryResult):
    """Print a recovery summary."""
    print()
    print("=" * 60)
    print("RECOVERY SUMMARY")
    print("=" * 60)
    print(f"  Table:           {result.database_name}.{result.table_name}")
    print(f"  Pages scanned:   {result.total_pages_scanned}")
    print(f"  Valid pages:     {result.valid_pages}")
    print(f"  Leaf pages:      {result.leaf_pages}")
    print(f"  Active records:  {result.active_records_recovered}")
    print(f"  Deleted records: {result.deleted_records_recovered}")
    print(f"  Total recovered: {result.records_recovered}")

    if result.create_table:
        print()
        print("  CREATE TABLE:")
        for line in result.create_table.split('\n'):
            print(f"    {line}")

    if result.warnings:
        print()
        print("  WARNINGS:")
        for w in result.warnings:
            print(f"    ! {w}")

    if result.errors:
        print()
        print("  ERRORS:")
        for e in result.errors:
            print(f"    x {e}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description='InnoDB Undrop for MySQL 8.0 - Recover dropped/deleted InnoDB data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Recover a dropped table
  python innodb_undrop.py --datadir /var/lib/mysql --db mydb --table users -o recovered.sql

  # Recover deleted rows only
  python innodb_undrop.py --datadir /var/lib/mysql --db mydb --table users --deleted-only -o deleted.sql

  # Recover with CREATE TABLE definition
  python innodb_undrop.py --datadir /var/lib/mysql --db mydb --table users \\
      --create-table "CREATE TABLE users(id INT PRIMARY KEY, name VARCHAR(100))" -o recovered.sql

  # Scan database for all recoverable tables
  python innodb_undrop.py --datadir /var/lib/mysql --db mydb --scan-all

  # Export as CSV
  python innodb_undrop.py --datadir /var/lib/mysql --db mydb --table users -o recovered.csv
        """,
    )

    # Core arguments
    parser.add_argument('--datadir', '-d',
                        help='MySQL data directory (containing ibdata1 and database subdirectories)')
    parser.add_argument('--database', '--db',
                        help='Database name')
    parser.add_argument('--table', '-t',
                        help='Table name to recover')

    # Recovery options
    parser.add_argument('--create-table',
                        help='CREATE TABLE statement (auto-detected from SDI if not provided)')
    parser.add_argument('--deleted-only',
                        action='store_true',
                        help='Recover only deleted rows (ignore active rows)')
    parser.add_argument('--active-only',
                        action='store_true',
                        help='Export only active rows (ignore deleted rows)')
    parser.add_argument('--checksum-algo',
                        type=int, choices=[0, 1, 2, 3, 4],
                        help='Checksum algorithm: 0=none, 1=innodb, 2=strict_innodb, 3=crc32, 4=strict_crc32')

    # Output options
    parser.add_argument('--output', '-o',
                        help='Output file path (default: <db>_<table>_recovered.sql)')
    parser.add_argument('--scan-all',
                        action='store_true',
                        help='Scan entire database for recoverable tables')

    # Debug options
    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        help='Verbose output')
    parser.add_argument('--debug',
                        action='store_true',
                        help='Debug output (very verbose)')

    args = parser.parse_args()

    setup_logging(verbose=args.verbose, debug=args.debug)

    if args.scan_all:
        return cmd_scan(args)
    else:
        return cmd_recover(args)


if __name__ == '__main__':
    sys.exit(main())
