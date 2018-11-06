import os
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import binascii

def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out
    
	## stripping rsa part from aes part
    rsa_data = f[0:512]
    aes_data = f[512:]
    
    # import private key for decrytion
    priv_key = RSA.importKey(open("private_encryption_key.pem").read())
    rsa_ciph = PKCS1_OAEP.new(priv_key)
    rsa = rsa_ciph.decrypt(rsa_data)
    
    # removing the iv
    rsa_iv = rsa[:16]
    rsa_key = rsa[16:32]
    
    #rsa_hash_old = rsa[32:]
    
    #rsa_ivkey = rsa_iv + rsa_key
    #rsa_hash_new = SHA512.new(rsa_ivkey)
    
    
    #decrypting the data that was encrypted with aes
    aes_cipher = AES.new(rsa_key, AES.MODE_CFB, rsa_iv)
    decoded_text = aes_cipher.decrypt(aes_data)

    print(decoded_text)
    return decoded_text
    
    ##code for decrypting valuables updates
    #encoded_text = f
    #priv_key = RSA.importKey(open("private_encryption_key.pem").read())
    #h = SHA512.new()
    #cipher = PKCS1_OAEP.new(priv_key)
    #decoded_text = cipher.decrypt(f)


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
