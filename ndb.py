def raise_on_invalid_magic(data: bytes):
    if data[0x3000+0xF:0x3000+0xF+3] != bytes([0xCD, 0xEF, 0x12]):
        raise RuntimeError("Invalid magic")

    # key = data[0x3000+0x12:0x3000+0x12+6]
    # count = int.from_bytes(data[0x3000+0x18:0x3000+0x18+4], "little")


def entry_data_by_name(data: bytes, name: bytes):
    bank_id = _bank_id_from_name(name)
    offset = _offset_by_bank_id(data, bank_id)

    while True:
        _name = _get_entry_name_at_offset(data, offset)
        if name == _name:
            return _get_entry_data_at_offset(data, offset)
        offset = _next_offset(data, offset)


def for_each_entry_name_and_data(data: bytes):
    for bank_id in range(0, 0x1000):
        offset = _offset_by_bank_id(data, bank_id)
        if offset == 0:
            continue
        _name = _get_entry_name_at_offset(data, offset)
        _data = _get_entry_data_at_offset(data, offset)
        yield _name, _data


def _bank_id_from_name(str: bytes):
    result = 0
    for c in str:
        result = c + ((result << 5) ^ (result >> 3))
    return result & 0xFFF


def _offset_by_bank_id(data: bytes, bank_id: int):
    return _next_offset(data, bank_id*3-0x3000)


def _next_offset(data: bytes, offset: int) -> int:
    return (int.from_bytes(data[0x3000+offset:0x3000+offset+3], "big") & 0x7FFFFF) * 0x100  # noqa


def _get_entry_name_at_offset(data: bytes, offset: int):
    assert offset > 0

    expected_len = int.from_bytes(data[0x3000+offset+6:0x3000+offset+6+3], "big")  # noqa

    result = bytearray()

    while len(result) < expected_len:
        len_to_copy = 0xF3
        if data[0x3000+offset] < 0x80:
            len_to_copy = 0xFD

        len_to_copy = min(len_to_copy, expected_len-len(result))

        src = 0xD
        if data[0x3000+offset] < 0x80:
            src += 3

        result.extend(
            data[0x3000+offset+src:0x3000+offset+src+len_to_copy]
        )

        offset = _next_offset(data, offset)

    return result


def _get_entry_data_at_offset(data: bytes, offset: int):
    ihavenoidea = int.from_bytes(data[0x3000+offset+6:0x3000+offset+6+3], "big")  # noqa
    entry_len = int.from_bytes(data[0x3000+offset+9:0x3000+offset+9+3], "big")  # noqa

    if entry_len == 0:
        return bytearray()

    y = 0

    while True:
        y += 0xFD if data[0x3000+offset] < 0x80 else 0xF3

        if not (y <= ihavenoidea):
            break

        offset = _next_offset(data, offset)

    z = y - ihavenoidea
    src = 0x100 - z

    result = bytearray()

    while True:
        z = min(z, entry_len - len(result))
        result.extend(data[0x3000+offset+src:0x3000+offset+src+z])

        if len(result) >= entry_len:
            break

        offset = _next_offset(data, offset)

        z = 0xF3
        src = 0xD
        if data[0x3000+offset] & 0x80 == 0:
            z = 0xFD
            src = 0x3

    return result
