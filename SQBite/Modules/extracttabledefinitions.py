import struct
import re
from Modules.btreeinteriorpage_processing import parse_interior_page
from Modules.btreeleafpage_processing import mainparse_leaf_page

# Constants for page types
TABLEINTERIOR_PAGE_TYPE = 5
TABLELEAF_PAGE_TYPE = 13

def extract_columns_and_types_from_sql(sql_statement):
    """
    Extracts column names and types from a CREATE TABLE statement.
    """
    columns = []
    match = re.search(r"CREATE\s+TABLE\s+\S+\s*\((.+)\)", sql_statement, re.S | re.I)
    
    if match:
        column_block = match.group(1)
        parts = re.findall(r'(?:[^,(]|\([^)]*\))+', column_block)

        for col_def in parts:
            col_def = col_def.strip()
            if col_def.upper().startswith(("CONSTRAINT", "PRIMARY", "UNIQUE", "FOREIGN", "CHECK")):
                continue

            col_parts = col_def.split()
            if not col_parts:
                continue

            col_name = col_parts[0].strip("`\"[]()")
            type_tokens = []

            for token in col_parts[1:]:
                token_upper = token.upper()
                if token_upper in ("NOT", "NULL", "PRIMARY", "KEY", "UNIQUE", "CHECK", "DEFAULT", "COLLATE", "REFERENCES"):
                    break
                type_tokens.append(token)

            col_type = " ".join(type_tokens) if type_tokens else "TEXT"
            columns.append((col_name, col_type))
    
    return columns

def extract_table_definitions_from_schema(db_file, page_size):
    """
    Extracts table definitions from sqlite_master, ensuring no duplicate columns.
    """
    db_file.seek(100)  # Start of Page 1
    page_data = db_file.read(page_size)

    rows = []
    page_type = page_data[0]
    
    if page_type == TABLEINTERIOR_PAGE_TYPE:  # Interior B-tree page
        child_pages = parse_interior_page(page_data, page_size, is_page_1=True)
        for child_page in child_pages:
            child_offset = (child_page - 1) * page_size
            db_file.seek(child_offset)
            child_data = db_file.read(page_size)
            if child_data[0] == TABLELEAF_PAGE_TYPE:  # Leaf page check
                rows.extend(mainparse_leaf_page(db_file, child_data, child_page, page_size))
    elif page_type == TABLELEAF_PAGE_TYPE:
        rows = mainparse_leaf_page(db_file, page_data, 1, page_size, is_page_1=True)
    else:
        print(f"[-] Page 1 is not a recognized B-tree page type: {page_type}")

    tables = []
    for row in rows:
        try:
            if len(row) >= 6 and (row[2] == b"table" or (isinstance(row[2], bytes) and row[2].decode('utf-8') == "table")):
                table_name = row[3].decode("utf-8", errors="ignore").strip()
                sql_statement = row[6].decode("utf-8", errors="ignore").strip()

                # Skip invalid SQL statements
                if not sql_statement.lower().startswith("create table"):
                    print(f" [!] Skipping table {table_name}, invalid SQL: {repr(sql_statement)}")
                    continue

                columns = list(dict.fromkeys(extract_columns_and_types_from_sql(sql_statement)))

                tables.append({"name": table_name, "columns": columns})

        except Exception as e:
            print(f"[-] Error parsing row: {e}")

    return tables
