import struct
from Modules.btreeinteriorpage_processing import parse_interior_page
from Modules.btreeleafpage_processing import mainparse_leaf_page

# Constants for page types
TABLEINTERIOR_PAGE_TYPE = 5
TABLELEAF_PAGE_TYPE = 13

def find_root_page(db_file, page_size):
    """
    Finds the root page for the tables in the sqlite_master table.
    """
    db_file.seek(100)  # Skip the SQLite header (page 1 starts after 100-byte header)
    page_data = db_file.read(page_size)

    page_type = page_data[0]
    root_pages = []

    if page_type == TABLEINTERIOR_PAGE_TYPE:
        child_pages = parse_interior_page(page_data, page_size, is_page_1=True)
        for child_page in child_pages:
            child_offset = (child_page - 1) * page_size
            db_file.seek(child_offset)
            child_data = db_file.read(page_size)

            if child_data[0] == TABLELEAF_PAGE_TYPE:
                try:
                    # Extract root page from sqlite_master leaf page
                    rows = mainparse_leaf_page(db_file, child_data, child_page, page_size, is_page_1=False)
                    for row in rows:
                        # Extract table name and root page
                        if len(row) >= 6 and row[2] == b"table":
                            table_name = row[3].decode("utf-8", errors="replace")
                            root_page = row[5] if isinstance(row[5], int) else struct.unpack(">I", row[5])[0]
                            root_pages.append({"name": table_name, "root_page": root_page})
                except Exception as e:
                    print(f"[!] Error parsing leaf page {child_page}: {e}")

    elif page_type == TABLELEAF_PAGE_TYPE:
        rows = mainparse_leaf_page(db_file, page_data, 1, page_size, is_page_1=True)
        for row in rows:
            if len(row) >= 6 and row[2] == b"table":
                table_name = row[3].decode("utf-8", errors="replace")
                root_page = row[5] if isinstance(row[5], int) else struct.unpack(">I", row[5])[0]
                root_pages.append({"name": table_name, "root_page": root_page})

    return root_pages

def traverse_table_btree(db_file, root_page, page_size, table_name):
    """
    Traverses the B-tree for a table and collects page numbers without processing leaf cells.
    """
    pages_to_process = [root_page]
    seen_pages = set()
    table_pages = []

    while pages_to_process:
        current_page = pages_to_process.pop(0)
        if current_page in seen_pages:
            continue
        seen_pages.add(current_page)

        page_offset = (current_page - 1) * page_size

        #Skips Virtual Tables
        if root_page == 0:
            #print(f"[!] Skipping Table: {table_name} - Virtual Table")
            continue
        
        try:
            db_file.seek(page_offset)
            page_data = db_file.read(page_size)
        except OSError as e:
            #print(f"[-] Error seeking to offset {page_offset} for page {current_page}: {e}")
            continue

        if len(page_data) != page_size:
            #print(f"[!] Incomplete read for page {current_page} (expected {page_size} bytes, got {len(page_data)} bytes).")
            continue

        page_type = page_data[0]

        if page_type == TABLEINTERIOR_PAGE_TYPE:  # Interior B-tree page
            child_pages = parse_interior_page(page_data, page_size)
            pages_to_process.extend(child_pages)
        elif page_type == TABLELEAF_PAGE_TYPE:  # Leaf B-tree page
            table_pages.append(current_page)
        #else:
            #print(f"[!] Skipping Table: {table_name} - Might be a WITHOUT ROWID Table")

    return table_pages

def parse_db_for_tables(db_file, page_size):
    """
    Parses the database to find all tables and traverse their B-trees, 
    collecting both table names and their associated page numbers.
    """
    all_table_pages = []
    
    # Find root pages for all tables
    root_pages = find_root_page(db_file, page_size)
    
    # Traverse each table's B-tree and collect page numbers
    for table in root_pages:
        table_name = table["name"]
        root_page = table["root_page"]
        table_pages = traverse_table_btree(db_file, root_page, page_size, table_name)
        
        # Store both table name and its pages in the list
        all_table_pages.append({"table_name": table_name, "pages": table_pages})

    return all_table_pages

