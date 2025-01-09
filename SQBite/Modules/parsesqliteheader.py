import struct

def parse_sqlite_header(file):
    """
    Parses the SQLite database file header.
    """
    header = file.read(100)
    if len(header) < 100:
        raise ValueError("File too small to be a valid SQLite database.")
    
    magic_string = header[:16]
    # Checks if the input file is a valid SQLite database 
    if magic_string != b'SQLite format 3\x00':
        print(f"Error: The file is not a valid SQLite database.")
        raise ValueError(f"Invalid SQLite database signature: {magic_string}")
    
    database_page_size = struct.unpack('>H', header[16:18])[0]
    page_size = 65536 if database_page_size == 1 else database_page_size
    auto_vacuum = struct.unpack('>I', header[52:56])[0]

    return {"page_size": page_size, "auto_vacuum": auto_vacuum}


