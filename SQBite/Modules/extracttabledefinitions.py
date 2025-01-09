import struct
from Modules.btreeinteriorpage_processing import parse_interior_page
from Modules.btreeleafpage_processing import mainparse_leaf_page

# Constants for page types
TABLEINTERIOR_PAGE_TYPE = 5
TABLELEAF_PAGE_TYPE = 13

def extract_table_definitions_from_schema(db_file, page_size):
    """
    Extracts table definitions from sqlite_master, with handling of Page 1 if it is 
	an interior or leaf page.
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
        print(f"Page 1 is not a recognized B-tree page type: {page_type}")

    tables = []
    for row in rows:
        try:
            if len(row) >= 3 and (row[2] == b"table" or (isinstance(row[2], bytes) and row[2].decode('utf-8') == "table")):
                table_name = row[3].decode("utf-8", errors="replace")
                root_page = row[5] if isinstance(row[5], int) else struct.unpack(">I", row[5])[0]
                tables.append({"name": table_name, "root": root_page})
        except Exception as e:
            print(f"Error parsing row: {e}")

    if not tables:
        print("No valid tables identified from sqlite_master.")

    return tables