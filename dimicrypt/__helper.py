def permutate(inp, perm_table, bit_len) -> int:
    tmp = 0
    for index in perm_table:
        tmp <<= 1
        tmp |= (inp >> (bit_len - index) & 1)
    return tmp


def halve(inp, bit_len) -> tuple:
    half_len = int(bit_len/2)
    return (inp >> half_len), (inp & (2**half_len - 1))


def join_halves(left, right, bit_len) -> int:
    tmp = left << bit_len
    return tmp | right


def split(inp, num, bit_len) -> tuple:
    tmp = []
    split_len = int(bit_len/num)
    mask = 2**split_len - 1
    for i in range(0, num):
        tmp.append(inp >> (bit_len - split_len*(i+1)) & mask)

    return tuple(tmp)


def merge(inp_list: list, inp_bit_size) -> int:
    tmp = 0
    for inp in inp_list:
        tmp <<= inp_bit_size
        tmp |= inp

    return tmp

