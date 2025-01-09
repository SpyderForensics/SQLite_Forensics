import struct

def parse_wal_header(wal_file):
    """
    Parses the WAL header
    """
    header = wal_file.read(32)
    if len(header) < 32:
        raise ValueError("File too small to be a valid WAL file.")

    magic, format_version, page_size, checkpoint, salt1, salt2, checksum1, checksum2 = struct.unpack(
        '>4s7i', header
    )

    # Convert the magic bytes to an integer directly for comparison
    magic_number = struct.unpack(">I", magic)[0]
    if magic_number not in {0x377F0682, 0x377F0683}:  # Valid SQLite WAL magic numbers
        raise ValueError(f"Invalid WAL file signature: {magic_number:#x}")

    return {"page_size": page_size}

