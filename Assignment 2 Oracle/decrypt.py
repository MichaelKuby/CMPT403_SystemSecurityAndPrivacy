import secrets
import subprocess
import sys


def replace(r_k, byte_string):
    # Convert the byte string to a mutable byte array
    byte_array = bytearray(byte_string)

    # Replace the byte at r_i with a new random byte
    byte_array[r_k] = secrets.token_bytes(1)[0]

    # Convert the byte array back to a byte string
    new_byte_string = bytes(byte_array)

    return new_byte_string


def check_oracle(filename, byte_string):
    with open(filename, 'wb') as newFile:
        newFile.write(byte_string)
    oracle = subprocess.check_output(['python', 'oracle.py', filename])
    return oracle[0]


def decrypt_first_byte(ciphertext, block_from_end):

    # Capture the appropriate block from the ciphertext
    y_N_start = (-16 * block_from_end)

    if block_from_end == 1:
        y_N = ciphertext[y_N_start:]
    else:
        y_N = ciphertext[y_N_start:y_N_start + 16]

    y_N_prev = ciphertext[y_N_start - 16:y_N_start]

    decrypt = None

    random_byteString = b''

    # Fill the block with 15 random bytes
    for i in range(15):
        random_byteString += secrets.token_bytes(1)

    for i in range(256):
        r_with_y_N = random_byteString + bytes([i]) + y_N

        # Check Oracle
        filename2 = 'output1'
        result = check_oracle(filename2, r_with_y_N)

        if result == 48:
            continue
        else:
            # Found i s.t. the oracle returned yes
            for k in range(15):
                r_with_y_N = replace(k, r_with_y_N)
                result2 = check_oracle(filename2, r_with_y_N)

                if result2 == 48:
                    # Oracle returned "no".
                    decrypt = i ^ k
                    break
                elif k < 14:
                    # Oracle returned yes but k < 15
                    continue
                else:
                    # Oracle returned yes and k == 15
                    decrypt = i ^ 15
                    break

            break

    # Decrypt x_n
    x_n_16 = decrypt ^ y_N_prev[-1]
    return bytes([x_n_16]), bytes([decrypt])


def decrypt_any_byte(ciphertext, block_from_end, byte_k, previous_decrypt):
    """
    :param ciphertext: The ciphertext to be decoded
    :param block_from_end: The number of blocks from the end of the ciphertexts. "End" block is n = 1
    :param byte_k: byte_15 recovered by decrypt_first_byte. byte_k ranges from 0 to 14 in reverse order.
    :param previous_decrypt: D(y_N)_{k+1} | D(y_N)_{k+2} | ... | D(y_N)_16 as a byte object
    :return: x_n_byte_k, D(y_N)_byte_k both in byte form
    """

    # Capture the appropriate block from the ciphertext
    y_N_start = (-16 * block_from_end)

    if block_from_end == 1:
        y_N = ciphertext[y_N_start:]
    else:
        y_N = ciphertext[y_N_start:y_N_start + 16]

    y_N_prev = ciphertext[y_N_start - 16:y_N_start]

    xor_previous_decrypt_bytearray = bytearray([val ^ byte_k for val in previous_decrypt])
    xor_previous_decrypt = bytes(xor_previous_decrypt_bytearray)

    # Fill the block with byte_k-1 random bytes
    random_byteString = b''
    for i in range(byte_k):
        random_byteString += secrets.token_bytes(1)

    # Ask Oracle Process begins
    i = 0
    current_decrypt = None
    while True:
        r_y_N = random_byteString + bytes([i]) + xor_previous_decrypt + y_N

        # Check Oracle
        filename2 = 'output2'
        result = check_oracle(filename2, r_y_N)

        if result == 48:
            # Oracle returned no
            i += 1
            continue
        else:
            # Found i s.t. the oracle returned yes
            # print(f"got here. i = {i}")
            current_decrypt = i ^ byte_k
            break

    # Decrypt x_n
    x_N_k = current_decrypt ^ y_N_prev[byte_k]
    return bytes([x_N_k]), bytes([current_decrypt])


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    filename = sys.argv[1]
    with open(filename, 'rb') as file:
        content = file.read()  # content is of class 'bytes'

    x = b''
    num_bytes = len(content)
    num_blocks = num_bytes // 16

    for block_n in range(1, num_blocks):
        # Get the last byte - indexed at 15
        x_N = b''
        decrypt_chain = b''

        x_N_last, decrypt_last = decrypt_first_byte(content, block_n)
        x_N += x_N_last
        decrypt_chain += decrypt_last
        # print(f"x_N block: {x_N}, first decrypt: {decrypt_chain}")

        for byte in reversed(range(15)):
            # Decrypt bytes 14 down to 0
            x_N_new, decrypt_new = decrypt_any_byte(content, block_n, byte, decrypt_chain)
            x_N = x_N_new + x_N
            decrypt_chain = decrypt_new + decrypt_chain
            # print(f"x_N block: {x_N}, decrypt chain block: {decrypt_chain}")

        # Append the current block to the encoded plaintext
        x = x_N + x

    # Decode to plaintext and print
    plaintext = x.decode('ascii')
    print(plaintext, end='')