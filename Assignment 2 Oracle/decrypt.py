import secrets
import subprocess


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

    # Append bytes i = 0 to 15
    for i in range(245, 256):
        r_copy = random_byteString + bytes([i])
        r_with_y_N = r_copy + y_N

        # Check Oracle
        filename = 'output.bin'
        result = check_oracle(filename, r_with_y_N)

        if result == 48:
            continue
        else:
            # Found i s.t. the oracle returned yes
            for k in range(16):
                r_with_y_N = replace(k, r_with_y_N)
                result2 = check_oracle(filename, r_with_y_N)

                if result2 == 48:
                    # Oracle returned "no".
                    decrypt = i ^ k
                    break
                elif k < 15:
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


def decrypt_any_byte(ciphertext, block_from_end, byte_k, previous_decrypt_list):
    # Capture the appropriate block from the ciphertext
    y_N_start = (-16 * block_from_end)

    if y_N_start + 16 == 0:
        y_N = ciphertext[y_N_start:]
    else:
        y_N = ciphertext[y_N_start:y_N_start + 16]

    y_N_prev = ciphertext[y_N_start - 16:y_N_start]

    random_byteString = b''
    xor_previous_decrypt = b''

    for val in previous_decrypt_list:
        new_val = val ^ (byte_k - 1)
        xor_previous_decrypt = bytes([new_val]) + xor_previous_decrypt

    # Fill the block with byte_k-1 random bytes
    for i in range(byte_k-1):
        random_byteString += secrets.token_bytes(1)

    # Ask Oracle Process begins
    i = 0
    current_decrypt = None
    while True:
        r = random_byteString + bytes([i]) + xor_previous_decrypt
        r_y_N = r + y_N

        # Check Oracle
        filename = 'output2'
        result = check_oracle(filename, r_y_N)

        if result == 48:
            # Oracle returned no
            i += 1
            print(i)
            continue
        else:
            # Found i s.t. the oracle returned yes
            print(f"got here. i = {i}")
            current_decrypt = i ^ (byte_k - 1)
            break

    # Decrypt x_n
    x_N_k = current_decrypt ^ y_N_prev[byte_k]
    return bytes([x_N_k]), previous_decrypt_list.append(bytes([current_decrypt]))


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    with open('ciphertext', 'rb') as file:
        content = file.read()  # content is of class 'bytes'

    x_N = b''
    n = 1
    # Decrypt the first byte
    x_N_current, decrypt_first = decrypt_first_byte(content, n)
    x_N += x_N_current
    print(f"x_N block: {x_N}, first decrypt: {decrypt_first}")

    decrypt_list = list(decrypt_first)

    # Decrypt the second byte
    b = 15
    x_N_new, decrypt_chain_main = decrypt_any_byte(content, n, b, decrypt_list)
    x_N = x_N_new + x_N
    print(f"x_N block: {x_N}, decrypt chain block: {decrypt_chain_main}")

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
