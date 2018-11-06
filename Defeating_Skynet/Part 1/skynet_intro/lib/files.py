import os
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA512, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import random
import binascii

# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []

###

def save_valuable(data):
    valuables.append(data)

def encrypt_for_master(data):
    # Encrypt the file so it can only be read by the bot master
    
    # random key and iv for aes cipher
    aes_key = os.urandom(16)
    iv = os.urandom(16)
    aes_cipher = AES.new(aes_key, AES.MODE_CFB, iv)
    # encrypt data with aes
    aes_enc = aes_cipher.encrypt(data)
    
    # import public key and encrypt aes key with rsa
    pub_key = RSA.importKey(open("pastebot.net/public_encryption_key.pem", "rb").read())
    cipher = PKCS1_OAEP.new(pub_key)

    encoded_text = cipher.encrypt(aes_key)
    fin_enc_data = aes_enc + encoded_text
    return fin_enc_data
    
    ## previous rsa only encryption code
    #pub_key = RSA.importKey(open("pastebot.net/public_encryption_key.pem", "rb")
    #hashed_key = SHA512.new(pub_key).digest()
    #hash = hashed_key.update(data)
    #return data

def upload_valuables_to_pastebot(fn):
    # Encrypt the valuables so only the bot master can read them
    valuable_data = "\n".join(valuables)
    valuable_data = bytes(valuable_data, "ascii")
    #hash the data to upload
    h = SHA512.new(valuable_data)
    #import public key
    upload_key = RSA.importKey(open("pastebot.net/public_encryption_key.pem", "rb").read())
    #encrypt with OAEP to send to pastebot
    cipher = PKCS1_OAEP.new(upload_key)
    encrypted_master = cipher.encrypt(h.digest() + valuable_data)
    encrypted_master = encrypt_for_master(valuable_data)

    # "Upload" it to pastebot (i.e. save in pastebot folder)
    f = open(os.path.join("pastebot.net", fn), "wb")
    f.write(encrypted_master)
    f.close()

    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

###

def verify_file(f):
    # Verify the file was sent by the bot master
    # TODO: For Part 2, you'll use public key crypto here
    # Naive verification by ensuring the first line has the "passkey"
    lines = f.split(bytes("\n", "ascii"))
    try:
        signature = binascii.unhexlify(lines[0])
    except:
        return False
    
    original_file = bytes("", "ascii")
    for i in range(1, len(lines)):
        if i == len(lines)-1:
            original_file += lines[i]
        else:
            original_file += lines[i] + bytes("\n", "ascii")
            
    print("Original File: \n" + str(original_file, "ascii") + "\n")

    print("Signature: " + str(lines[0], "ascii") + "\n")
    
    public_key = RSA.importKey(open("pastebot.net/public_signing_key.pem").read())
    h = SHA512.new()
    h.update(original_file)
    
    print("Computed hash: " + h.hexdigest() + "\n")
    verifier = PKCS1_PSS.new(public_key)
    if verifier.verify(h, signature):
        return True
    else:
        return False
        

def process_file(fn, f):
    if verify_file(f):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    process_file(fn, f)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)

###

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(fn)
    sconn.send(filestore[fn])

def run_file(f):
    # If the file can be run,
    # run the commands
    pass
