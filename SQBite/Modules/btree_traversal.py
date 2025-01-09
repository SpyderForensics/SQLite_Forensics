import struct
from Modules.btreeinteriorpage_processing import parse_interior_page
from Modules.btreeleafpage_processing import mainparse_leaf_page

# Constants for page types
TABLEINTERIOR_PAGE_TYPE = 5
TABLELEAF_PAGE_TYPE = 13

def traverse_table_btree(db_file, root_page, page_size, source_file, table_name):
    """
    Traverses the B-tree for a table and processes Leaf pages
    """
    pages_to_process = [root_page]
    seen_pages = set()
    extracted_cells = []

    while pages_to_process:
        current_page = pages_to_process.pop(0)
        if current_page in seen_pages:
            continue
        seen_pages.add(current_page)

        page_offset = (current_page - 1) * page_size
        if page_offset < 0: #or page_offset >= os.path.getsize(db_file.name):
            print(f"  - Skipping Table: {table_name} is a Virtual Table")
            continue

        db_file.seek(page_offset)
        page_data = db_file.read(page_size)
        page_type = page_data[0]

        if page_type == TABLEINTERIOR_PAGE_TYPE:  # Interior B-tree page
            child_pages = parse_interior_page(page_data, page_size)
            pages_to_process.extend(child_pages)
        elif page_type == TABLELEAF_PAGE_TYPE:  # Leaf B-tree page
            cells = mainparse_leaf_page(db_file, page_data, current_page, page_size)
            for cell in cells:
                cell_offset = page_offset + cell[0]  
                extracted_cells.append((source_file, current_page, table_name, cell_offset, *cell[1:]))
        else:
            print(f"  - Skipping Table: {table_name} - Might be a WITHOUT ROWID Table")
    return extracted_cells