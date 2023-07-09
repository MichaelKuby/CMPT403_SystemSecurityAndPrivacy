# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.

def fileToBytes(filename):
    with open(filename, 'rb') as file:
        content = file.read()
    return list(content)


def textToBytes(string):
    byteString = string.encode('utf-8')
    return byteString


def xorBytes(bytes1, bytes2):
    xorResult = [x ^ y for x, y in zip(bytes1, bytes2)]
    return xorResult


def toAscii(byteString):
    result = [chr(x) for x in byteString]
    return "".join(result)


def crib_drag(ciphertext, crib):
    crib_length = len(crib)
    for i in range(crib_length + 1): #len(ciphertext) -
        potential_plaintext = ciphertext[i:i + crib_length]
        xor_result = xorBytes(potential_plaintext, crib)
        print(f"{i}: {toAscii(xor_result)} \t\t")


if __name__ == '__main__':
    # Retrieve the contents of the cypher texts in byte form as lists
    c0Bytes = fileToBytes('ctext0')
    c1Bytes = fileToBytes('ctext1')

    # XOR the two cypher texts together
    cXOR = xorBytes(c0Bytes, c1Bytes)

    # Guess in plaintext:
    plaintext1 = "The show's final two seasons, especially season eight, received more criticism. Season seven was praised for its action sequences and focused central characters, but received criticism for its pace and plot developments that were said to have \"defied logic\". Writing for Vox, Emily VanDerWerff cited the departure from the source material as a reason for the \"circular storytelling.\" Critical reception for season eight was mixed. The Guardian said there was the \"rushed business\" of the plot which \"failed to do justice to its characters or its actors\". Writing for The Hollywood Reporter, Maureen R"

    # Convert guess to bytecode
    guessBytes = textToBytes(plaintext1)

    # For each possible
    crib_drag(cXOR, guessBytes)

    plaintext2 = "Musk is president of the Musk Foundation, which states its purpose is to provide solar-power energy systems in disaster areas; support research, development, and advocacy (for interests including human space exploration, pediatrics, renewable energy and \"safe artificial intelligence\"); and support science and engineering educational efforts. Since 2002, the foundation has made ozir 350 contributions. Around half were to scientific research or education nonprofits. Notable beneficiaries include the Wikimedia Foundation, his alma mater the University of Pennsylvania, and Kimbal's Big Green. Vox "
    encoding = 'ascii'
    byte_length1 = len(plaintext1.encode(encoding))
    byte_length2 = len(plaintext2.encode(encoding))
    print(byte_length1)
    print(byte_length2)
# See PyCharm help at https://www.jetbrains.com/help/pycharm/
