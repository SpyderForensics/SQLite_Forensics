import struct
from Modules.varints import single_varint, multi_varint

def parse_interior_page(page_data, page_size, is_page_1=False):
    """
    Parses an interior B-tree page and extracts child page numbers.
    """
    if page_data[0] != 5:  # Ensure it is an interior B-tree page
        raise ValueError("Page is not an interior B-tree page.")

    # Adjust pointer base for Page 1
    pointer_base = 100 if is_page_1 else 0

    # Number of cells on the page
    num_cells = struct.unpack(">H", page_data[3:5])[0]

    # Calculate cell pointers
    if is_page_1:
        cell_pointers = [
            struct.unpack(">H", page_data[12 + i * 2:14 + i * 2])[0] - pointer_base
            for i in range(num_cells)
        ]
    else:
        cell_pointers = [
            struct.unpack(">H", page_data[12 + i * 2:14 + i * 2])[0]
            for i in range(num_cells)
        ]

    child_pages = []
    for pointer in cell_pointers:
        if pointer < 0 or pointer >= len(page_data):  # Ensure valid pointer
            print(f" [-] Invalid cell pointer {pointer}. Skipping.")
            continue
        cell_data = page_data[pointer:]
        child_page_number = struct.unpack(">I", cell_data[:4])[0]
        child_pages.append(child_page_number)

    # Rightmost pointer for interior pages
    rightmost_page = struct.unpack(">I", page_data[8:12])[0]
    child_pages.append(rightmost_page)
	
    return child_pages
