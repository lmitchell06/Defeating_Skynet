import os
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
import binascii

def generate_keys():
    signing_key = RSA.generate(4096)
    encryption_key = RSA.generate(4096)

    pub_s = open("pastebot.net/public_signing_key.pem", 'wb')
    pub_s.write(signing_key.publickey().exportKey('PEM', None, 1))

    pub_e = open("pastebot.net/public_encryption_key.pem", 'wb')
    pub_e.write(encryption_key.publickey().exportKey('PEM', None, 1))

    priv_s = open("private_signing_key.pem", 'wb')
    priv_s.write(signing_key.exportKey('PEM', None, 1))

    priv_e = open("private_encryption_key.pem", 'wb')
    priv_e.write(encryption_key.exportKey('PEM', None, 1))

def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!
    # generate_keys()

    key_file = open("private_signing_key.pem", 'r').read();
    
    key = RSA.importKey(key_file, None)
    h = SHA512.new()
    h.update(f)
    signer = PKCS1_PSS.new(key)
    signature = signer.sign(h)

    print("Signature: " + str(binascii.hexlify(signature), "ascii") + "\n")
    print("Computed hash: " + h.hexdigest() + "\n")

    public_key = key.publickey()
    
    return binascii.hexlify(signature) + bytes("\n", "ascii") + f
    


if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
