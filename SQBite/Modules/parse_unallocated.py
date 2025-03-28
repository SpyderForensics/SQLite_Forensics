import struct
import string

def extract_printable_from_unallocated(page_data, page_number, frame_number, file_offset_for_page):
    """
    Extracts printable characters from unallocated space of B-tree pages.
    Returns (printable_data, unallocated_offset)
    """
    try:
        page_size = len(page_data)
        if page_size < 8:
            return "", None

        # Page header fields
        page_type = page_data[0]
        if page_type not in {2, 5, 10, 13}:  # Only B-tree pages
            return "", None

        cell_count = struct.unpack(">H", page_data[3:5])[0]
        cell_content_offset = struct.unpack(">H", page_data[5:7])[0]

        # Calculate unallocated space boundaries
        cell_pointers_end = 8 + cell_count * 2
        unallocated_start = cell_pointers_end
        unallocated_end = cell_content_offset if cell_content_offset > 0 else page_size

        if unallocated_start >= unallocated_end:
            return "", None

        unallocated_data = page_data[unallocated_start:unallocated_end]
        printable_data = ''.join(ch for ch in unallocated_data.decode(errors="replace") if ch in string.printable)

        # Calculate phyiscal offset 
        unallocated_offset = file_offset_for_page + unallocated_start

        return printable_data, unallocated_offset

    except Exception as e:
        print(f"[!] Error extracting from page {page_number} (frame {frame_number}): {e}")
        return "", None
        
def extract_printable_from_freelisttrunk(page_data, page_number, frame_number, file_offset_for_page):
    """
    Extracts printable characters from unallocated space of B-tree pages.
    """
    try:
        page_size = len(page_data)
        if page_size < 8:
            return "", None

        # Calculate end of the freelist array
        num_entries = struct.unpack('>I', page_data(4-7))[0]
        array_end = 8 + num_entries * 4
        unallocated_start = array_end
        unallocated_end = page_size

        if unallocated_start >= unallocated_end:
            return "", None

        unallocated_data = page_data[unallocated_start:unallocated_end]
        printable_data = ''.join(ch for ch in unallocated_data.decode(errors="replace") if ch in string.printable)

        # Calculate absolute offset
        unallocated_offset = file_offset_for_page + unallocated_start

        return printable_data, unallocated_offset

    except Exception as e:
        print(f"[!] Error extracting from page {page_number} (frame {frame_number}): {e}")
        return "", None
