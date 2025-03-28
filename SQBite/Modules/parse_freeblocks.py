import struct
import string

def extract_printable_from_freeblock(page_data, page_number, frame_number, file_offset_for_page):
    """
    Extracts printable data from the freeblocks
    """
    freeblocks = []
    # Extract the freeblock offset (2 bytes from position 1 to 3)
    freeblock_offset = struct.unpack(">H", page_data[1:3])[0]
    freeblock_pointer = freeblock_offset

    # Process freeblocks until the pointer is 0 (end of the freeblocks list)
    while freeblock_pointer != 0:
        # Ensure the pointer does not go out of bounds
        if freeblock_pointer + 4 > len(page_data):  # The minimum size to read is 4 bytes for pointer and length
            print(f" [-] Invalid freeblock pointer at page {page_number}, offset {freeblock_pointer}")
            break

        # Extract the next freeblock pointer and its length
        next_freeblock_offset = freeblock_pointer
        next_freeblock = struct.unpack(">H", page_data[next_freeblock_offset:next_freeblock_offset + 2])[0]
        freeblock_length = struct.unpack(">H", page_data[next_freeblock_offset + 2:next_freeblock_offset + 4])[0]

        # Ensure that the freeblock length doesn't cause us to exceed the page data length
        # if next_freeblock_offset + 4 + freeblock_length > len(page_data):
            # print(f"[-] Freeblock data exceeds page size at page {page_number}, offset {next_freeblock_offset}")
            # break

        # Extract the freeblock data
        freeblock_data = page_data[next_freeblock_offset + 4: next_freeblock_offset + 4 + freeblock_length]

        # Filter for printable characters only
        printable_data = ''.join(ch for ch in freeblock_data.decode(errors="replace") if ch in string.printable)

        # Calculate the absolute offset for this freeblock in the WAL file
        absolute_freeblock_offset = file_offset_for_page + next_freeblock_offset

        # Append the freeblock's offset and printable data to the list
        freeblocks.append((absolute_freeblock_offset, printable_data))

        # Move to the next freeblock pointer
        freeblock_pointer = next_freeblock

    return freeblocks

