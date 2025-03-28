import struct

def extract_freelist_pagenumbers(db_file, page_size, first_freelist_trunk): 
    freelist_pages = []
    freelist_trunk_pages = []
    freelist_trunk = first_freelist_trunk

    while freelist_trunk != 0:
        db_file.seek((freelist_trunk - 1) * page_size)  # Seek to the freelist trunk page
        next_trunk_page = db_file.read(4)  # Read the next trunk page (4 bytes)
        next_trunk_page_number = struct.unpack(">I", next_trunk_page)[0]  # Unpack as a 4-byte unsigned integer
        
        freelist_trunk_pages.append(next_trunk_page_number)  # Append the actual next trunk page number

        num_entries = struct.unpack(">I", db_file.read(4))[0]  # Read number of entries (4 bytes)
        
        for _ in range(num_entries):
            entry_page_number = struct.unpack(">I", db_file.read(4))[0]  # Unpack page number for freelist entry
            freelist_pages.append(entry_page_number)  # Append the page number
        
        freelist_trunk = next_trunk_page_number  # Set the current trunk page to the next one

    return freelist_pages, freelist_trunk_pages
