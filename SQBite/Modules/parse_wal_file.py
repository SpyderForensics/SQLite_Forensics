import struct
import os
import math
from collections import defaultdict
from Modules.extracttabledefinitions import extract_table_definitions_from_schema
from Modules.btreeinteriorpage_processing import parse_interior_page
from Modules.btreeleafpage_processing import walparse_leaf_page
from Modules.parsewalheader import parse_wal_header
from Modules.parsesqliteheader import parse_sqlite_header

# Constants for page types
TABLEINTERIOR_PAGE_TYPE = 5
TABLELEAF_PAGE_TYPE = 13

def calculate_pointermappages(auto_vacuum, page_size, total_pages):
    """ 
    Calculates the page numbers for pointer map pages.
    """
    pointer_pages = []
    
    # Checks if auto_vacuum is enabled
    if auto_vacuum > 0:
        # Sets the pointer counter at 1 as we know the first pointer map
        pointer_counter = 1
        # Calculates the number of 5-byte entries that can be stored on the page
        pointer_entries = math.floor(page_size / 5)
        # Sets pointer number to 0
        pointer_number = 0
        
        # While the pointer_number is less than or equal to the total number of pages in the database
        while pointer_number <= total_pages:
            # Calculates the pointer number
            pointer_number = ((pointer_entries * pointer_counter) + 2 + pointer_counter)
            # Breaks the loop when the pointer_number is greater than total pages
            # Added this due to some weird anomaly where the last pointer number generated was higher than total_pages
            if pointer_number > total_pages:
                break
            # Adds the pointer number to the Pointer Page list
            pointer_pages.append(pointer_number)
            # Increments the pointer counter before the next iteration
            pointer_counter += 1

    return pointer_pages

def parse_wal_file(wal_path, db_path):
    """
    Parses the SQLite WAL file and stores page number and offset for comparison.
    """
    rows = []
    wal_frames = [] 

    with open(db_path, "rb") as db_file:
        header = parse_sqlite_header(db_file)
        auto_vacuum = header["auto_vacuum"]
        page_size = header["page_size"]
        total_pages = os.path.getsize(db_path) // page_size
        pointer_pages = calculate_pointermappages(auto_vacuum, page_size, total_pages)

    with open(wal_path, "rb") as wal_file:
        print(f"\nProcessing {os.path.basename(wal_path)}...\n")
        header = parse_wal_header(wal_file)
        page_size = header["page_size"]

        frame_number = 0
        while True:
            frame_header = wal_file.read(24)
            if len(frame_header) < 24:
                break
            frame_number += 1

            page_data = wal_file.read(page_size)
            if not page_data:
                continue

            # Extract page number and calculate file offset for the page
            page_number = struct.unpack(">I", frame_header[0:4])[0]
            file_offset_for_page = wal_file.tell() - page_size

            # Skip pointer map pages if auto-vacuum is enabled
            if auto_vacuum > 0 and (page_number == 2 or page_number in pointer_pages):
                print(f" - Skipping WAL Frame {frame_number} (Page {page_number}): Pointer Map Page")
                continue

            if page_data[0] == TABLEINTERIOR_PAGE_TYPE:
                wal_frames.append((page_number, file_offset_for_page))
                print(f" - Skipping WAL Frame {frame_number} (Page {page_number}): B-tree Interior Page")

            # Process leaf pages and identify table names
            elif page_data[0] == TABLELEAF_PAGE_TYPE:
                print(f" - Processing WAL Frame {frame_number} (Page {page_number})")
                try:
                    table_name, source = build_page_table_mapping(db_path, page_size, wal_path, wal_frames, target_page=page_number)
                except ValueError:
                    table_name, source = "Unknown", "Unknown"
                print(f"  - Table Name: {table_name}")

                cells = walparse_leaf_page(wal_file, page_data, page_number, page_size)
                for cell in cells:
                    cell_offset = file_offset_for_page + cell[0]
                    rows.append((os.path.basename(wal_path), page_number, table_name, cell_offset, *cell[1:]))

            else:
                print(f" - Skipping WAL Frame {frame_number} (Page {page_number}): Not a Table B-tree Page")

    return rows

def build_page_table_mapping(db_path, page_size, wal_path, wal_frames, target_page, frame_number=None):
    """
    Identifies the table name for a page by working backward through Interior pages in the WAL. 
	If not found in WAL then traverses the b-trees in the MainDB
    """
    #print(f"WAL Interior Pages: {wal_frames}")
    wal_frame_data = defaultdict(list)
    for frame in wal_frames:
        wal_frame_data[frame[0]].append(frame[1])

    def read_walpage(page_number):
        """Reads a page from the WAL file using the latest entry for the page."""
        if page_number in wal_frame_data:
            offset = wal_frame_data[page_number][-1]  
            with open(wal_path, "rb") as wal_file:
                wal_file.seek(offset)
                return wal_file.read(page_size)
        return None

    def read_dbpage(page_number):
        """Reads a page from the main database file."""
        page_offset = (page_number - 1) * page_size
        with open(db_path, "rb") as db_file:
            db_file.seek(0, os.SEEK_END)
            db_file_size = db_file.tell()
            if page_offset >= db_file_size or page_offset < 0:
                raise ValueError(f"Invalid page offset for page number {page_number}.")
            db_file.seek(page_offset)
            return db_file.read(page_size)

    # Extract root pages from sqlite_master table
    with open(db_path, "rb") as db_file:
        tables = extract_table_definitions_from_schema(db_file, page_size)
        root_pages = {table["root"]: table["name"] for table in tables}

    # Backward traversal through WAL frames
    already_checked_pages = set()
    index = len(wal_frames) - 1

    while target_page not in root_pages and index >= 0:
        page_number, offset = wal_frames[index]
        index -= 1

        # Avoid re-checking pages
        if page_number in already_checked_pages:
            continue
        already_checked_pages.add(page_number)

        # Read the WAL page data
        page_data = read_walpage(page_number)
        if not page_data:
            continue

        page_type = page_data[0]

        # If the page is an interior page, process child pages
        if page_type == TABLEINTERIOR_PAGE_TYPE:
            child_pages = parse_interior_page(page_data, page_size)
            if target_page in child_pages:
                print(f"  - Parent Table Interior Page Found in WAL. Moving up the B-tree")
                target_page = page_number  # Update target_page to the current interior page to move up the b-tree
                already_checked_pages.clear()
                continue

    # If the target page is identified as a root page in WAL
    if target_page in root_pages:
        print(f"  - Table Root Page Found in WAL")
        return root_pages[target_page], "WAL" 

    # If not found in WAL, revert to searching the main database
    print(f"  - Parent Table Interior Page Not Found in WAL. Searching Main Database File..")
    already_checked_pages.clear()
    for table in tables:
        root_page = table["root"]
        table_name = table["name"]
        pages_to_process = [root_page]

        while pages_to_process:
            current_page = pages_to_process.pop(0)
            if current_page in already_checked_pages:
                continue
            already_checked_pages.add(current_page)

            try:
                page_data = read_dbpage(current_page)
                page_type = page_data[0]
            except ValueError:
                continue

            if page_type == TABLEINTERIOR_PAGE_TYPE:
                child_pages = parse_interior_page(page_data, page_size)
                if target_page in child_pages:
                    print(f"  - Table Root Page Found in Main Database File")
                    return table_name, "Main Database"
                pages_to_process.extend(child_pages)

    return "Unknown", "Unknown"  # If no match is found











