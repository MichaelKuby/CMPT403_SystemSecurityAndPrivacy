from Crypto.Cipher import AES

key = b'super secret key'
iv = b'CMPT 403 Test IV'
msg = bytearray(b'Alice and Bob in Wonderland')

#padding
rounddown = int((len(msg))/16) * 16
diff = len(msg) - rounddown

for i in range(16 - diff):
    msg.append(diff)
#encrypt
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(bytes(msg))

f = open("ciphertext", "wb")
f.write(iv)
f.write(ciphertext)
f.close()
