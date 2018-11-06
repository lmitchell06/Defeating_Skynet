import struct
from lib.helpers import read_hex
from Crypto.Cipher import XOR
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import HMAC
from Crypto.Hash import SHA512
from Crypto import Random
import hashlib
import binascii
import time
import struct


from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.shared_hash = None
        self.last_message_timestamp = None
        self.dos_counter = None
        self.last_message_bytes = None
        self.initiate_session()
        
    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
        
        # This is our counter for our counter mode AES 256 cipher
        #ctr = Counter.new(128)
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.shared_hash.hexdigest()))
            self.dos_counter = 0


        # self.cipher = XOR.new(shared_hash[:4]) - This is the old crappy cipher

        # This is the new AES cipher using counter mode
        iv = Random.new().read(AES.block_size)
        self.cipher = AES.new(self.shared_hash.digest(), AES.MODE_CFB, iv)


        #Creates a new HMAC, used to verify that the data has not been tampered with (Authenticity)
    def send(self, data):
        
        
        if self.cipher:
            if self.shared_hash:
                h = HMAC.new(self.shared_hash.digest(), digestmod=SHA512)
                h.update(data)
                data = data + h.digest()
                timeFloat = time.time()
                timeBytes = struct.pack("d", timeFloat) #Creates a byte time format
                print("Sent Timestamp: " + str(struct.unpack("d", timeBytes)[0]))
                print("Sent HMAC: " + str(binascii.hexlify(h.digest())))
                data = data + timeBytes #Appends the timestamp to the data
                self.last_message_bytes = data
                
            encrypted_data = self.cipher.encrypt(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        
        #512 bits is 64 bytes. In hex, 2 characters make up a single byte. Therefore, our HMAC is the last 128 hex characters of the recieved message.
        
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            data = self.cipher.decrypt(encrypted_data)
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data
            
        #Splits the hmac from the message to make sure that the two are the same
        if self.shared_hash:

            timestamp = data[-8:]
            hmac = data[-72:-8]
            message = data[:-72]

            timestampFloat = struct.unpack("d", timestamp)[0]
            timeReceived = time.time()

            calculatedHmac = HMAC.new(self.shared_hash.digest(), digestmod=SHA512)
            calculatedHmac.update(message)

            hmac = str(binascii.hexlify(hmac))
            calculatedHmac = str(binascii.hexlify(calculatedHmac.digest()))

            print("Received Message: " + str(message, "ascii"))
            print("Received HMAC: " + hmac)
            print("Calculated HMAC: " + calculatedHmac)
            print("Received Timestamp: " + str(struct.unpack("d", timestamp)[0]))

            timeSinceRecievedTimestamp = timeReceived - timestampFloat

            if timeSinceRecievedTimestamp > 3: #If it has been more than 3 seconds since the message was originally sent then this is probably a replay attack
                print("We are in the middle of a replay attack. Terminating connection...")
                self.close()
                return bytes("Invalid Message Received", "ascii")
            if self.last_message_timestamp:
                timeSinceLastMessage = timeReceived - self.last_message_timestamp
                if  timeSinceLastMessage < 0.5: #If the it has been less than 10 milliseconds since the last message, increment the DOS counter
                    self.dos_counter += 1
                if self.dos_counter >= 100: #After 100 super fast messages, we can be pretty sure we're in the middle of a DOS attack. Who would type that fast?
                    print("We are experiencing a DOS attack. Terminating connection...")
                    self.close()
            if hmac != calculatedHmac:
                print("The message has been altered in transmission! Terminating connection...")
                self.close()
                return bytes("Invalid Message Received", "ascii")
            self.last_message_timestamp = timestampFloat



            return message

        else:
            return data

        #These testing functions all throw weird errors

    def simReplay(self):
        encrypted_data = self.cipher.encrypt(self.last_message_bytes)
        
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)
        echo = self.recv()
        
    def simDOS(self):
        for i in range(0,101):
            self.send(bytes("Welcome to DOSville", "ascii"))
            
    def simIntegrity(self):
        data = self.last_message_bytes
        
        timestamp = data[-8:]
        hmac = data[-72:-8]
        message = data[:-72]

        message = bytes("Welcome to INTEGRITYville", "ascii")

        newData = message + hmac + timestamp
        encrypted_data = self.cipher.encrypt(newData)

        pkt_len = struct.pack('H', len(newData))
        self.conn.sendall(pkt_len)
        self.conn.sendall(newData)
        echo = self.recv()
        
    def close(self):
        self.conn.close()
