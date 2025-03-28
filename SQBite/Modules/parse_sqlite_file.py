import struct
import os
from Modules.parsesqliteheader import parse_sqlite_header
from Modules.findtable import parse_db_for_tables
from Modules.btreeleafpage_processing import mainparse_leaf_page
from Modules.parse_unallocated import extract_printable_from_unallocated, extract_printable_from_freelisttrunk
from Modules.parse_freeblocks import extract_printable_from_freeblock
from Modules.freelistpagenumbers import extract_freelist_pagenumbers
from Modules.calculate_pointermappages import calculate_pointer_pages

# Constants for page types
TABLEINTERIOR_PAGE_TYPE = 5
TABLELEAF_PAGE_TYPE = 13
INDEXINTERIOR_PAGE_TYPE = 2
INDEXLEAF_PAGE_TYPE = 10
MAINDBHEADER = 83

def parse_sqlite_file(db_path):
    """
    Parses the SQLite Main Database file
    """
    with open(db_path, "rb") as db_file:
        print(f"\nProcessing {os.path.basename(db_path)}...\n")
        header = parse_sqlite_header(db_file)
        page_size = header["page_size"]
        auto_vacuum = header["auto_vacuum"]
        first_freelist_trunk = header["first_freelist_trunk_page"]
        total_pages = os.path.getsize(db_path) // page_size

        all_table_pages = parse_db_for_tables(db_file, page_size)
        
        # Identify freelist pages
        freelist_pages, freelist_trunk_pages = extract_freelist_pagenumbers(db_file, page_size, first_freelist_trunk) 
        #print(f"Freelist Pages: {freelist_pages}")

        table_pages_map = {}
        for table in all_table_pages:
            for page in table["pages"]:
                table_pages_map[page] = table["table_name"]

        pointer_pages = calculate_pointer_pages(auto_vacuum, page_size, total_pages)

        records = []
        recovered_records = []
        freetable_name = "freelist"

        # Process each page in the database file
        for page_number in range(1, total_pages + 1):
            db_file.seek((page_number - 1) * page_size)
            page_data = db_file.read(page_size)
            if not page_data:
                continue

            # Skip pointer map pages if auto_vacuum is enabled
            if auto_vacuum > 0 and (page_number == 2 or page_number in pointer_pages):
                print(f"[!] Skipping Page {page_number}: Pointer Map Page")
                continue

            file_offset_for_page = (page_number - 1) * page_size
            page_type = page_data[0]
            
            # Parse unallocated space from freelist trunk pages
            if page_number == first_freelist_trunk or page_number in freelist_trunk_pages:
                print(f"[!] Processing Page {page_number}: Freelist Trunk Page - Unallocated Space Only")
                unallocated, unallocated_offset = extract_printable_from_freelisttrunk(page_data, page_number, 0, file_offset_for_page)
                if unallocated:
                    recovered_records.append((os.path.basename(db_path), "N/A", page_number, "Freelist Trunk Page", freetable_name, "Page Unallocated Space", unallocated_offset, unallocated))            
            
            #Parses Freelist Pages
            if page_number in freelist_pages:
                # Parse unallocated space from Table Interior freelist pages
                if page_type == TABLEINTERIOR_PAGE_TYPE:
                    print(f"[!] Processing Page {page_number}: Freelist - Table Interior Page - Unallocated Space Only")
                    unallocated, unallocated_offset = extract_printable_from_unallocated(page_data, page_number, 0, file_offset_for_page)
                    if unallocated:
                        recovered_records.append((os.path.basename(db_path), "N/A", page_number, "Freelist Table Interior", freetable_name, "Page Unallocated Space", unallocated_offset, unallocated))
                
                # Parse unallocated space from Index Interior freelist pages
                elif page_type == INDEXINTERIOR_PAGE_TYPE:
                    print(f"[!] Processing Page {page_number}: Freelist - Index Interior Page - Unallocated Space Only")
                    unallocated, unallocated_offset = extract_printable_from_unallocated(page_data, page_number, 0, file_offset_for_page)
                    if unallocated:
                        recovered_records.append((os.path.basename(db_path), "N/A", page_number, "Freelist Index Interior", freetable_name, "Page Unallocated Space", unallocated_offset, unallocated))

                # Parse cells, freeblocks and Unallocated Space from Table Leaf Freelist Pages
                elif page_type == TABLELEAF_PAGE_TYPE:
                    print(f"[+] Processing Page {page_number}: Freelist Table Leaf Page")
                    
                    table_name = freetable_name

                    if table_name:
                        try:
                            cells = mainparse_leaf_page(db_file, page_data, page_number, page_size)
                            for cell in cells:
                                cell_offset = file_offset_for_page + cell[0]
                                records.append((os.path.basename(db_path), "N/A", page_number, "Freelist", freetable_name, cell_offset, *cell[1:]))

                            # Extract unallocated and freeblock data from the page
                            unallocated, unallocated_offset = extract_printable_from_unallocated(page_data, page_number, 0, file_offset_for_page)
                            if unallocated:
                                recovered_records.append((os.path.basename(db_path), "N/A", page_number, "Freelist Table Leaf", freetable_name, "Page Unallocated Space", unallocated_offset, unallocated))

                            freeblocks = extract_printable_from_freeblock(page_data, page_number, 0, file_offset_for_page)
                            for freeblock_offset, freeblock in freeblocks:
                                recovered_records.append((os.path.basename(db_path), "N/A", page_number, "Freelist Table Leaf", freetable_name, "Freeblock", freeblock_offset, freeblock))

                        except Exception as e:
                            print(f" [-] Error parsing freelist leaf page {page_number}: {e}")

                # Parse unallocated space from Index Leaf freelist pages
                elif page_type == INDEXLEAF_PAGE_TYPE:
                    print(f"[!] Processing Page {page_number}: Freelist - Index Leaf Page - Unallocated Space Only")
                    unallocated, unallocated_offset = extract_printable_from_unallocated(page_data, page_number, 0, file_offset_for_page)
                    if unallocated:
                        recovered_records.append((os.path.basename(db_path), "N/A", page_number, "Freelist Index Leaf", freetable_name, "Page Unallocated Space", unallocated_offset, unallocated))

            # Parse unallocated space from table interior pages
            elif page_type == TABLEINTERIOR_PAGE_TYPE:
                print(f"[!] Processing Page {page_number}: B-tree Table Interior Page - Unallocated Space Only")
                unallocated, unallocated_offset = extract_printable_from_unallocated(page_data, page_number, 0, file_offset_for_page)
                if unallocated:
                    recovered_records.append((os.path.basename(db_path), "N/A", page_number, "B-tree Table Interior", "Not Known", "Page Unallocated Space", unallocated_offset, unallocated))
            
            # Parse unallocated space from index interior pages
            elif page_type == INDEXINTERIOR_PAGE_TYPE:
                print(f"[!] Processing Page {page_number}: B-tree Index Interior Page - Unallocated Space Only")
                unallocated, unallocated_offset = extract_printable_from_unallocated(page_data, page_number, 0, file_offset_for_page)
                if unallocated:
                    recovered_records.append((os.path.basename(db_path), "N/A", page_number, "B-tree Index Interior", "Not Known", "Page Unallocated Space", unallocated_offset, unallocated))

            # Parse cells, freeblocks and Unallocated Space from Table Leaf Pages
            elif page_type == TABLELEAF_PAGE_TYPE:
                print(f"[+] Processing Page {page_number}: B-tree Table Leaf Page")

                # Find the table name by checking if the page is part of the B-tree of any table
                table_name = table_pages_map.get(page_number)

                if table_name:
                    try:
                        cells = mainparse_leaf_page(db_file, page_data, page_number, page_size)
                        for cell in cells:
                            cell_offset = file_offset_for_page + cell[0]
                            records.append((os.path.basename(db_path), "N/A", page_number, "Allocated", table_name, cell_offset, *cell[1:]))

                        # Extract unallocated and freeblock data from the page
                        unallocated, unallocated_offset = extract_printable_from_unallocated(page_data, page_number, 0, file_offset_for_page)
                        if unallocated:
                            recovered_records.append((os.path.basename(db_path), "N/A", page_number, "B-tree Table Leaf", "Not Known", "Page Unallocated Space", unallocated_offset, unallocated))

                        freeblocks = extract_printable_from_freeblock(page_data, page_number, 0, file_offset_for_page)
                        for freeblock_offset, freeblock in freeblocks:
                            recovered_records.append((os.path.basename(db_path), "N/A", page_number, "B-tree Table Leaf", table_name, "Freeblock", freeblock_offset, freeblock))

                    except Exception as e:
                        print(f" [-]  Error parsing leaf page {page_number}: {e}")

            # Parse unallocated space from index leaf pages
            elif page_type == INDEXLEAF_PAGE_TYPE:
                print(f"[!] Processing Page {page_number}: B-tree Index Leaf Page - Unallocated Space Only")
                unallocated, unallocated_offset = extract_printable_from_unallocated(page_data, page_number, 0, file_offset_for_page)
                if unallocated:
                    recovered_records.append((os.path.basename(db_path), "N/A", page_number, "B-tree Index Leaf", "Not Known", "Page Unallocated Space", unallocated_offset, unallocated))

            # Skipping unknown and overflow pages (Records with overflow are reconstructed for table leaf cells
            elif page_type == 0:
                if all(b == 0 for b in page_data):
                    print(f"[!] Skipping Page {page_number}: Empty Page")
                else:
                    print(f"[!] Skipping Page {page_number}: Overflow Page")

            # Skipping Page 1
            elif page_type == MAINDBHEADER:
                print(f"[!] Skipping Page {page_number}: Main Database File Header and Schema")

            else:
                print(f"[!] Skipping Page {page_number} (Offset {file_offset_for_page}): Not a Table B-tree Page")

    return records, recovered_records
