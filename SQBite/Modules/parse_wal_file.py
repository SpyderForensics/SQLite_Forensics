import struct
import os
import math
from collections import defaultdict
from Modules.findtable import parse_db_for_tables
from Modules.btreeinteriorpage_processing import parse_interior_page
from Modules.btreeleafpage_processing import walparse_leaf_page
from Modules.parsewalheader import parse_wal_header
from Modules.parsesqliteheader import parse_sqlite_header
from Modules.parse_unallocated import extract_printable_from_unallocated
from Modules.parse_freeblocks import extract_printable_from_freeblock

# Constants for page types
TABLEINTERIOR_PAGE_TYPE = 5
TABLELEAF_PAGE_TYPE = 13
INDEXINTERIOR_PAGE_TYPE = 2
INDEXLEAF_PAGE_TYPE = 10
MAINDBHEADER = 83

def calculate_pointermappages(auto_vacuum, page_size, total_pages):
    """ 
    Calculates the page numbers for pointer map pages.
    """
    pointer_pages = []
    
    # Checks if auto_vacuum is enabled
    if auto_vacuum > 0:
        pointer_counter = 1
        pointer_entries = math.floor(page_size / 5)
        pointer_number = 0
        while pointer_number <= total_pages:
            pointer_number = ((pointer_entries * pointer_counter) + 2 + pointer_counter)
            if pointer_number > total_pages:
                break
            pointer_pages.append(pointer_number)
            pointer_counter += 1

    return pointer_pages

def parse_wal_file(wal_path, db_path):
    """
    Parses the SQLite WAL file and stores page number and offset for comparison.
    """
    records = []
    recovered_records = []
    wal_frames = [] 

    # Parse information from the main database file header
    with open(db_path, "rb") as db_file:
        header = parse_sqlite_header(db_file)
        auto_vacuum = header["auto_vacuum"]
        page_size = header["page_size"]
        total_pages = os.path.getsize(db_path) // page_size
        pointer_pages = calculate_pointermappages(auto_vacuum, page_size, total_pages)

        # Extract table page mappings before parsing WAL frames
        all_table_pages = parse_db_for_tables(db_file, page_size)

    # Parse the WAL file and process frames
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
                print(f"[!] Skipping WAL Frame {frame_number} (Page {page_number}): Pointer Map Page")
                continue

            # Parse unallocated space from Table Interior pages
            if page_data[0] == TABLEINTERIOR_PAGE_TYPE:
                wal_frames.append((page_number, file_offset_for_page))
                print(f"[!] Processing WAL Frame {frame_number} (Page {page_number}): B-tree Table Interior Page - Unallocated Space Only")
                unallocated, unallocated_offset = extract_printable_from_unallocated(page_data, page_number, frame_number, file_offset_for_page)
                if unallocated:
                    recovered_records.append((os.path.basename(wal_path), frame_number, page_number, "B-tree Table Interior", "Not Known", "Page Unallocated Space", unallocated_offset, unallocated))
            
            # Parse unallocated space from Index Interior pages
            elif page_data[0] == INDEXINTERIOR_PAGE_TYPE:
                wal_frames.append((page_number, file_offset_for_page))
                print(f"[!] Processing WAL Frame {frame_number} (Page {page_number}): B-tree Index Interior Page - Unallocated Space Only")
                unallocated, unallocated_offset = extract_printable_from_unallocated(page_data, page_number, frame_number, file_offset_for_page)
                if unallocated:
                   recovered_records.append((os.path.basename(wal_path), frame_number, page_number, "B-tree Table Interior", "Not Known", "Page Unallocated Space", unallocated_offset, unallocated))

            # Parse unallocated space from index leaf pages
            elif page_data[0] == INDEXLEAF_PAGE_TYPE:
                wal_frames.append((page_number, file_offset_for_page))
                print(f"[!] Processing WAL Frame {frame_number} (Page {page_number}): B-tree Index Leaf Page - Unallocated Space Only")
                unallocated, unallocated_offset = extract_printable_from_unallocated(page_data, page_number, frame_number, file_offset_for_page)
                if unallocated:
                    recovered_records.append((os.path.basename(wal_path), frame_number, page_number, "Index Table Leaf", "Not Known", "Page Unallocated Space", unallocated_offset, unallocated))

            # Skipping unknown and overflow pages (Need to work on code to rebuild records with overflow pages in the wal)
            elif page_data[0] == 0:
                wal_frames.append((page_number, file_offset_for_page))

                if all(byte == 0 for byte in page_data):
                    print(f"[!] Skipping WAL Frame {frame_number} (Page {page_number}): Unknown: Empty Page")
                    page_type = "Unknown: Empty Page"
                else:
                    print(f"[!] Skipping WAL Frame {frame_number} (Page {page_number}): Overflow Page")
                    page_type = "Overflow Page"
            
            # Parse cells, freeblocks and Unallocated Space from Leaf Pages (This includes Freelist pages)
            elif page_data[0] == TABLELEAF_PAGE_TYPE:
                print(f"[+] Processing WAL Frame {frame_number} (Page {page_number}): B-tree Table Leaf Page")

                try:
                    table_name, source = build_page_table_mapping(db_path, page_size, wal_path, wal_frames, target_page=page_number, all_table_pages=all_table_pages)
                except ValueError:
                    table_name, source = "Unknown", "Unknown"

                cells = walparse_leaf_page(wal_file, page_data, page_number, page_size)
                for cell in cells:
                    cell_offset = file_offset_for_page + cell[0]
                    records.append((os.path.basename(wal_path), frame_number, page_number, "Allocated", table_name, cell_offset, *cell[1:]))
                unallocated, unallocated_offset = extract_printable_from_unallocated(page_data, page_number, frame_number, file_offset_for_page)
                if unallocated:
                    recovered_records.append((os.path.basename(wal_path), frame_number, page_number, "B-tree Table Leaf", "Not Known", "Page Unallocated Space", unallocated_offset, unallocated))
                    
                freeblocks = extract_printable_from_freeblock(page_data, page_number, frame_number, file_offset_for_page)
                for freeblock_offset, freeblock in freeblocks:
                    recovered_records.append((os.path.basename(db_path), frame_number, page_number, "B-tree Table Leaf", table_name, "Freeblock", freeblock_offset, freeblock))
			
            # Skipping Page 1 (Need to use this later to identify freelist pages in the wal.
            elif page_data[0] == MAINDBHEADER:
                print(f"[!] Skipping WAL Frame {frame_number} (Page {page_number}): Main Database Header + Schema")

            else:
                print(f"[!] Skipping WAL Frame {frame_number} (Page {page_number}) (File Offset {file_offset_for_page}): Not a Table B-tree Page")

    return records, recovered_records


def build_page_table_mapping(db_path, page_size, wal_path, wal_frames, target_page, frame_number=None, all_table_pages=None):
    """
    Identifies the table name for a page by working backward through Interior pages in the WAL. 
    If not found in WAL, it processes pages in the MainDB.
    """
    wal_frame_data = defaultdict(list)
    for frame in wal_frames:
        wal_frame_data[frame[0]].append(frame[1])

    def read_page(page_number, is_wal=True):
        """Reads a page from the WAL or DB based on the flag."""
        if is_wal:
            return read_walpage(page_number)
        else:
            return read_dbpage(page_number)

    def read_walpage(page_number):
        """Reads a page from the WAL file."""
        with open(wal_path, "rb") as wal_file:
            page_offset = (int(page_number) - 1) * page_size 
            wal_file.seek(page_offset)
            return wal_file.read(page_size)

    def read_dbpage(page_number):
        """Reads a page from the main database file."""
        page_number = int(page_number)
        page_offset = (page_number - 1) * page_size
        with open(db_path, "rb") as db_file:
            db_file.seek(0, os.SEEK_END)
            db_file_size = db_file.tell()
            if page_offset >= db_file_size or page_offset < 0:
                raise ValueError(f" [-] Invalid page offset for page number {page_number}.")
            db_file.seek(page_offset)
            return db_file.read(page_size)

    # Check if target page exists in the precomputed table pages list
    for table in all_table_pages:
        if target_page in table["pages"]:
            return table["table_name"], "WAL"

    # Backward traversal through WAL frames (if the page wasn't found in the root pages)
    already_checked_pages = set()
    index = len(wal_frames) - 1

    while target_page not in all_table_pages and index >= 0:
        page_number, offset = wal_frames[index]
        index -= 1

        if page_number in already_checked_pages:
            continue
        already_checked_pages.add(page_number)

        page_data = read_page(page_number, is_wal=True)
        if not page_data:
            continue

        page_type = page_data[0]

        if page_type == TABLEINTERIOR_PAGE_TYPE:
            child_pages = parse_interior_page(page_data, page_size)
            if target_page in child_pages:
                target_page = page_number
                already_checked_pages.clear()
                continue

    return "Unknown", "Unknown"  # If no match is found
