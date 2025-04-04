import struct
import math
from Modules.varints import single_varint, multi_varint

def handle_overflow(initial_payload, cell_offset, page_size, filesource, initial_payload_length, remaining_bytes):
    """
    Handles overflow pages for the main SQLite database file only.
    """

    overflow_data = initial_payload[:-4]
    overflow_page_number = struct.unpack(">I", initial_payload[-4:])[0]
    
    visited_pages = set()

    while overflow_page_number != 0 and remaining_bytes > 0:
        overflow_offset = (overflow_page_number - 1) * page_size
        filesource.seek(overflow_offset)
        overflow_page_data = filesource.read(page_size)

        # Extract the next overflow page number
        next_overflow_page_number = struct.unpack(">I", overflow_page_data[:4])[0]

        # Calculate how many bytes to read from the current overflow page
        bytes_to_read = min(remaining_bytes, page_size - 4)
        
        # Collect only the required remaining bytes
        overflow_data += overflow_page_data[4:4 + bytes_to_read]
        remaining_bytes -= bytes_to_read

        # Update the next overflow page number
        overflow_page_number = next_overflow_page_number
    #print(f"Overflow Payload: {overflow_data}")
    return overflow_data

def parse_cell(cell_data, cell_offset, page_size, filesource):

    payload_length, offset = single_varint(cell_data)
    
    row_id, length = single_varint(cell_data[offset:])
    offset += length

    header_length, header_varint_len = single_varint(cell_data[offset:])
    offset += header_varint_len

    column_types, header_parsed_length = multi_varint(cell_data[offset:offset + header_length - header_varint_len])
    offset += header_parsed_length

    # Overflow calculations
    U = page_size 
    P = payload_length
    X = U - 35
    M = math.floor(((U - 12) * 32 / 255) - 23)
    K = M + ((P - M) % (U - 4))

    if P > X and K <= X:
        initial_payload_length = K
        remaining_bytes = P - K
        initial_payload = cell_data[offset : offset + initial_payload_length + 4]
        cell_data = handle_overflow(initial_payload, cell_offset, page_size, filesource, initial_payload_length, remaining_bytes)
        offset = 0  
        #print(f"Overflow Payload: {cell_data}")

    elif P > X and K > X:
        initial_payload_length = M
        remaining_bytes = P - M
        initial_payload = cell_data[offset : offset + initial_payload_length + 4]
        cell_data = handle_overflow(initial_payload, cell_offset, page_size, filesource, initial_payload_length, remaining_bytes)
        offset = 0
        #print(f"Overflow Payload: {cell_data}")

    elif P <= X:
        initial_payload_length = P
        cell_data = cell_data[offset : offset + initial_payload_length]
        offset = 0

    # Decode column values
    columns = []
    for i, col_type in enumerate(column_types):
        try:
            column_value, col_length = decode_column_value(col_type, cell_data, offset)
        except Exception as e:
            print(f" [!] Failed to decode column {i}: {e}")
            break

        columns.append(column_value)
        offset += col_length

    return row_id, columns, cell_offset

def parse_walcell(cell_data, cell_offset, page_size, filesource):
    """
    Parses a single SQLite cell for WAL files.
    - Extracts only the initial payload.
    - Stops decoding columns if the end of the initial payload is reached.
    """
    # Decode the length of the payload and the row ID
    payload_length, offset = single_varint(cell_data)
    row_id, length = single_varint(cell_data[offset:])
    offset += length

    # Read header length and parse column types
    header_length = cell_data[offset]
    offset += 1
    column_types, header_parsed_length = multi_varint(cell_data[offset:offset + header_length - 1])
    offset += header_parsed_length

    # Overflow calculations
    U = page_size
    P = payload_length
    X = U - 35
    M = math.floor(((U - 12) * 32 / 255) - 23)
    K = M + ((P - M) % (U - 4))

    # Only extract the initial payload on the WAL page
    if P > X and K <= X:
        initial_payload_length = K
        print(f" [!] Record with RowID: {row_id} contains overflow data. Only initial payload extracted.")
    elif P > X and K > X:
        initial_payload_length = M
        print(f" [!] Record with RowID: {row_id} contains overflow data. Only initial payload extracted.")
    else:
        initial_payload_length = P

    adjusted_initial_payload_length = initial_payload_length - header_length

    # Decode columns up to the adjusted payload length
    columns = []
    start_offset = offset

    for i, col_type in enumerate(column_types):
        relative_offset = offset - start_offset

        try:
            column_value, col_length = decode_column_value(col_type, cell_data, offset)
        except Exception as e:
            print(f" [!] Failed to decode column {i}: {e}")
            break

        if relative_offset + col_length > adjusted_initial_payload_length:
            if col_length == 0:
                columns.append(column_value)

        columns.append(column_value)
        offset += col_length

    return row_id, columns, cell_offset

def mainparse_leaf_page(db_file, page_data, current_page, page_size, is_page_1=False):
    """
    Extracts rows from SQLite B-tree leaf pages in MainDB.
    """
    filesource = db_file
    rows = []

    if len(page_data) < 8:
        return rows

    page_type = page_data[0]
    if page_type != 13:  # Only process B-tree leaf pages
        return rows

    num_cells = struct.unpack(">H", page_data[3:5])[0]

    # If this is Page 1, adjust the pointer offsets
    if is_page_1:
        cell_pointers = [
            struct.unpack(">H", page_data[8 + i * 2:10 + i * 2])[0] - 100  # Adjust pointer for Page 1
            for i in range(num_cells)
        ]
    else:
        cell_pointers = [
            struct.unpack(">H", page_data[8 + i * 2:10 + i * 2])[0]
            for i in range(num_cells)
        ]

    for pointer in cell_pointers:
        if pointer < 0 or pointer >= len(page_data):  # Ensure valid pointer
            continue

        cell_data = page_data[pointer:]
        try:
            row_id, columns, cell_offset = parse_cell(cell_data, pointer, page_size, filesource)
            rows.append([cell_offset, row_id, *columns])
        except Exception as e:
            print(f" [-] Page {current_page}: Error parsing record at page offset {pointer}: {str(e).encode('ascii', errors='ignore').decode('ascii')}")
            continue

    return rows
	
def walparse_leaf_page(wal_file, page_data, page_number, page_size, is_page_1=False):
    """
    Extracts rows from SQLite B-tree leaf pages in WAL file.
    """
    filesource = wal_file
    rows = []
    current_page = page_number 

    if len(page_data) < 8:
        return rows

    page_type = page_data[0]
    if page_type != 13:  # Only process B-tree leaf pages
        return rows

    num_cells = struct.unpack(">H", page_data[3:5])[0]

    # If this is Page 1, adjust the pointer offsets
    if is_page_1:
        cell_pointers = [
            struct.unpack(">H", page_data[8 + i * 2:10 + i * 2])[0] - 100  # Adjust pointer for Page 1
            for i in range(num_cells)
        ]
    else:
        cell_pointers = [
            struct.unpack(">H", page_data[8 + i * 2:10 + i * 2])[0]
            for i in range(num_cells)
        ]

    for pointer in cell_pointers:
        if pointer < 0 or pointer >= len(page_data):  # Ensure valid pointer
            continue
        cell_data = page_data[pointer:]
        try:
            row_id, columns, cell_offset = parse_walcell(cell_data, pointer, page_size, filesource)
            rows.append([cell_offset, row_id, *columns])
        except Exception as e:
            print(f" [-] Page {current_page}: Error parsing record at page offset {pointer}: {str(e).encode('ascii', errors='ignore').decode('ascii')}")
            continue

    return rows

def decode_column_value(col_type, data, offset):
    """
    Decodes a single column value based on the SQLite serial type.
    """
    if col_type == 0:  # NULL
        return None, 0
    elif col_type == 1:  # INTEGER 8-bit
        return struct.unpack(">b", data[offset:offset + 1])[0], 1
    elif col_type == 2:  # INTEGER 16-bit
        return struct.unpack(">h", data[offset:offset + 2])[0], 2
    elif col_type == 3:  # INTEGER 24-bit
        return int.from_bytes(data[offset:offset + 3], "big"), 3
    elif col_type == 4:  # INTEGER 32-bit
        return struct.unpack(">i", data[offset:offset + 4])[0], 4
    elif col_type == 5:  # INTEGER 48-bit
        return int.from_bytes(data[offset:offset + 6], "big"), 6
    elif col_type == 6:  # INTEGER 64-bit
        return struct.unpack(">q", data[offset:offset + 8])[0], 8
    elif col_type == 7:  # FLOAT
        return struct.unpack(">d", data[offset:offset + 8])[0], 8
    elif col_type == 8:  # Integer 0
        return 0, 0
    elif col_type == 9:  # Integer 1 
        return 1, 0
    elif col_type >= 12 :  # BLOB
        blob_length = (col_type - 12) // 2
        return data[offset:offset + blob_length], blob_length
    elif col_type >= 13:  # Text
        text_length = (col_type - 13) // 2
        return data[offset:offset + text_length].decode("utf-8", errors="replace"), text_length
    raise ValueError(f"Unsupported column type: {col_type}")