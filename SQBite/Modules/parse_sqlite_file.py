import struct
import os
from Modules.parsesqliteheader import parse_sqlite_header
from Modules.btree_traversal import traverse_table_btree
from Modules.extracttabledefinitions import extract_table_definitions_from_schema

# Constants for page types
TABLEINTERIOR_PAGE_TYPE = 5
TABLELEAF_PAGE_TYPE = 13

def parse_sqlite_file(db_path):
    """
    Parses the SQLite Main Database file
    """
    with open(db_path, "rb") as db_file:
        print(f"Processing {os.path.basename(db_path)}...\n")
        header = parse_sqlite_header(db_file)
        page_size = header["page_size"]

        # Extract root pages and table definitions
        tables = extract_table_definitions_from_schema(db_file, page_size)
        
        if not tables:
            print(f"{os.path.basename(db_path)} - No tables found in the SQLite schema.")

        rows = []
        for table in tables:
            if table["name"] != "sqlite_master":
                root_page = table["root"]
                print(f" - Processing Table: {table['name']}")
                rows.extend(traverse_table_btree(db_file, root_page, page_size, os.path.basename(db_path), table["name"]))
    return rows