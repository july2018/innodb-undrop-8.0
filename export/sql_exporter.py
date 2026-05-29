"""
SQL Exporter - Generate SQL INSERT statements from recovered data
"""

import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


def export_to_sql(result, output_path: str,
                  include_deleted: bool = True,
                  separate_deleted: bool = True) -> str:
    """
    Export recovered records as SQL statements.

    Args:
        result: RecoveryResult object
        output_path: Output file path
        include_deleted: Whether to include deleted records
        separate_deleted: Whether to output deleted records separately
    """
    lines = []

    # Header
    lines.append('-- InnoDB Undrop for MySQL 8.0 - Recovery Output')
    lines.append(f'-- Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
    lines.append(f'-- Database: {result.database_name}')
    lines.append(f'-- Table: {result.table_name}')
    lines.append(f'-- Pages scanned: {result.total_pages_scanned}')
    lines.append(f'-- Valid pages: {result.valid_pages}')
    lines.append(f'-- Leaf pages: {result.leaf_pages}')
    lines.append(f'-- Active records recovered: {result.active_records_recovered}')
    lines.append(f'-- Deleted records recovered: {result.deleted_records_recovered}')
    lines.append(f'-- Total records recovered: {result.records_recovered}')
    lines.append('')

    # CREATE TABLE statement
    if result.create_table:
        lines.append('-- Original table structure')
        lines.append(result.create_table)
        lines.append('')

    # Warnings
    if result.warnings:
        lines.append('-- WARNINGS:')
        for w in result.warnings:
            lines.append(f'--   {w}')
        lines.append('')

    # Active records
    if result.records:
        lines.append(f'-- Active records ({len(result.records)} rows)')
        lines.append('SET FOREIGN_KEY_CHECKS=0;')
        lines.append('')

        for record in result.records:
            sql = build_insert_statement(
                result.table_name,
                record,
                result.fields,
            )
            if sql:
                lines.append(sql)

        lines.append('')
        lines.append('SET FOREIGN_KEY_CHECKS=1;')
        lines.append('')

    # Deleted records
    if include_deleted and result.deleted_records:
        if separate_deleted:
            lines.append(f'-- Deleted records ({len(result.deleted_records)} rows)')
            lines.append('-- These records were DELETE-marked or in the free list')
            lines.append('SET FOREIGN_KEY_CHECKS=0;')
            lines.append('')

            for record in result.deleted_records:
                sql = build_insert_statement(
                    result.table_name,
                    record,
                    result.fields,
                    comment='RECOVERED DELETED ROW',
                )
                if sql:
                    lines.append(sql)

            lines.append('')
            lines.append('SET FOREIGN_KEY_CHECKS=1;')

    # Summary
    lines.append('')
    lines.append(f'-- STATUS: {result.records_recovered} records recovered')

    sql_content = '\n'.join(lines)

    if output_path:
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(sql_content)
        logger.info(f"SQL output written to: {output_path}")

    return sql_content


def build_insert_statement(table_name: str, record: Dict[str, Any],
                            fields: List = None,
                            comment: str = None) -> Optional[str]:
    """Build a SQL INSERT statement from a record dict."""
    # Filter out internal fields
    data_fields = {k: v for k, v in record.items()
                   if not k.startswith('_')}

    if not data_fields:
        return None

    columns = []
    values = []

    for col_name, value in data_fields.items():
        if value is None:
            values.append('NULL')
        elif isinstance(value, (int, float)):
            values.append(str(value))
        elif isinstance(value, str):
            if value.startswith('[') and value.endswith(']'):
                # External data marker
                values.append(f"'{escape_sql(value)}'")
            else:
                values.append(f"'{escape_sql(value)}'")
        elif isinstance(value, bytes):
            values.append(f"0x{value.hex()}")
        else:
            values.append(f"'{escape_sql(str(value))}'")

        columns.append(f'`{col_name}`')

    comment_str = f' -- {comment}' if comment else ''
    sql = (f"INSERT INTO `{table_name}` ({', '.join(columns)}) "
           f"VALUES ({', '.join(values)});{comment_str}")

    return sql


def escape_sql(value: str) -> str:
    """Escape special characters for SQL strings."""
    return value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n").replace("\r", "\\r")


def export_to_csv(result, output_path: str,
                  include_deleted: bool = True,
                  separate_files: bool = True) -> str:
    """
    Export recovered records as CSV files.
    """
    import csv
    import io

    base_path = output_path.rsplit('.', 1)[0] if '.' in output_path else output_path

    def write_csv(records, path):
        if not records:
            return

        # Get column names from first record
        columns = [k for k in records[0].keys() if not k.startswith('_')]

        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
        with open(path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
            writer.writeheader()
            for record in records:
                row = {k: v for k, v in record.items() if not k.startswith('_')}
                writer.writerow(row)

        logger.info(f"CSV output written to: {path}")

    # Active records
    if result.records:
        write_csv(result.records, f"{base_path}.csv")

    # Deleted records
    if include_deleted and result.deleted_records and separate_files:
        write_csv(result.deleted_records, f"{base_path}_deleted.csv")

    return base_path
