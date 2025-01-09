def single_varint(data, index=0):
    """
    Processes a single Varint and returns its value and length.
    """
    varint = 0
    for i in range(9):
        byte = data[index + i]
        varint = (varint << 7) | (byte & 0x7F)
        if byte < 0x80:
            return varint, i + 1
    raise ValueError("Invalid varint")


def multi_varint(data):
    """
    Processes multiple Varints and returns a list of values and total length.
    """
    varints = []
    index = 0
    while index < len(data):
        try:
            varint, varint_length = single_varint(data, index)
            varints.append(varint)
            index += varint_length
        except ValueError:
            break
    return varints, index
