import struct

def extract_freelist_pagenumbers(db_file, page_size, first_freelist_trunk): 
    freelist_pages = []
    freelist_trunk_pages = []

    if first_freelist_trunk != 0:
        freelist_trunk_pages.append(first_freelist_trunk)

    freelist_trunk = first_freelist_trunk

    while freelist_trunk != 0:
        db_file.seek((freelist_trunk - 1) * page_size)

        next_trunk_page = db_file.read(4)
        next_trunk_page_number = struct.unpack(">I", next_trunk_page)[0]

        if next_trunk_page_number != 0:
            freelist_trunk_pages.append(next_trunk_page_number)

        num_entries = struct.unpack(">I", db_file.read(4))[0]

        for _ in range(num_entries):
            entry_page_number = struct.unpack(">I", db_file.read(4))[0]
            if entry_page_number != 0:
                freelist_pages.append(entry_page_number)

        freelist_trunk = next_trunk_page_number

    return freelist_pages, freelist_trunk_pages

