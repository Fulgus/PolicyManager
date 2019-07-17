from pyfirmata import Arduino, util
import socket
import time
from ecies import encrypt, decrypt
import re
import sys
import binascii
import hashlib
import Cryptodome.Cipher as cip
from Cryptodome.Cipher import DES, DES3

board = Arduino("/dev/ttyUSB0")

msgDelete = '04db097a50318ac5e62299fce462b72adcd85a138692f03c7fe970153581227c054ac24f4ca4131e4d58571b33ac14bcfe8b34addd709defac9b32f34753d55214a8d43a0d215eae8d35170b4794abeef1c15752733cb551625d2f9794e9de002018407f807cfcf76cf7c8cf64900f09e2626db1982f0618e49d2419ec076171fbda9aa6ad3446eadb3a6b3a5a746c91bc813c4d2a73e43e20de7ccccf97529072132c08e1352d41337705e89251e8a39786c53cdc332f97705b04d369756fa22175a672200aee037f4e9f20c99a96b6e03028c35640ee5f246f3a16632e7252ea577b209f49c6f0b511f504e9328afcf423aeb804c6f2f750b0acdaea1fea40d77e00b0165f52eef553d4f88068f114b73a44e482cb343a95fac0317e32b53a8d71db2b598a4d9dd166b780b9d64444a9700dab2e48ac4732891221c4de22ff76bd476bf2f7a87d5179de7aebd81c67d3c1156e0dda737c5975ce83bb6e121619264a1a6c7eba1ebb5a6353dc613406137ac1edb277ccceda9256ec9be2dd8a7a6c340ebd2af3732754ffadddc8853380ed3065f68dff2ac988e3f86a2b8f893aeaae9dc7ba19632b96d77f8ba55db2064193a0262606870174f19532c04cc012f1d5aea06e3bf70cb765e9a41a83fe45ea0ca714ba82186f21c2282703edf313ae081ce9a1009f0540f774565030f1ff3e3ef5b5127bde4b658a8143e72bb3815187182688654c9605056844b04cd3cf278ed3ba9507923cdd4affe68576e7899ea9a170d02167e07fb738500a49ef87e1804be2f986a2cee4f21086f6cadd5dd321d95951552a7f021dfa2c822bea83b196fd8e94d32f'

def receiveConn():
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = "192.168.0.27"
    port = 2005 
    soc.bind((host, port))
    soc.listen(1)


    conn, addr = soc.accept()

    print("Got connection from",addr)

    length_of_message_part1 = int.from_bytes(conn.recv(4), byteorder=sys.byteorder)
    msg = conn.recv(length_of_message_part1).decode("UTF-8")
    print(msg)
    print("----")
    return msg

#This key is supposed to be stored in a safe place of the node
#This devidce only supports DES and DES3 cipher
storedKey = "cff8bb3c92184e61fc767047c1d230c3a74863ad675d5ca053f59a19b8e062ad"  #jose privKey


def readMessage(message):
    '''
    Gets a given message, decrypts it using ECC and separates
    some parameters. These are: 
        
        - Cipher used
        - IV/Nonce
        - Key used
        - Message

    Parameters
    ----------

    message : String given from System input file

    '''

    privKey = storedKey
        
    try:
        decryptedMsgBytes = decrypt(privKey, binascii.unhexlify(message.strip().encode()))
        decryptedMsg = decryptedMsgBytes.decode('utf-8')
        linesMsg = decryptedMsg.split('|')
        cipher_used = linesMsg[0]
        ivNonce = linesMsg[1]
        key = linesMsg[2]
        msg = linesMsg[3]
        hashmsg = linesMsg[4]
        
        decryptedSignature = decrypt(privKey, binascii.unhexlify((hashmsg.encode())))
        hashToCheck = hashlib.sha512(msg.encode('utf-8')).hexdigest()

        if decryptedSignature.decode() != hashToCheck:
            sys.exit('Integrity is not guaranteed.')

    except:
        print("Message is not encrypted in Public Key of node. Please change it.")
        sys.exit()

    return cipher_used, ivNonce, key, msg

def decryptMsg(cipher_used, key_used, ivNonce, msg_to_decrypt):
    '''
    Gets a given message and certain parameters to decrypt it.

    Parameters
    ----------

    cipher_used : String

        The used cipher in encryption.

    key_used : bytes object

        Key used in encryption.

    ivNonce : bytes object

        IV or Nonce used, according to cipher used.

    msg_to_decrypt : bytes object

        Original message to decrypt.

    '''
    key = key_used
    msg = msg_to_decrypt
    if re.search("DES3" ,cipher_used):
        if re.search("CBC", cipher_used):
            cipherMode = cip.DES3.new(key, cip.DES3.MODE_CBC, iv=ivNonce)
            decryptedMsg = cipherMode.decrypt(msg)
        else:
            cipherMode = cip.DES3.new(key, cip.DES3.MODE_EAX, nonce=ivNonce)
            decryptedMsg = cipherMode.decrypt(msg)

    if re.search("^DES" ,cipher_used):
        if re.search("CBC", cipher_used):
            cipherMode = cip.DES.new(key, cip.DES.MODE_CBC, iv=ivNonce)
            decryptedMsg = cipherMode.decrypt(msg)
        else:
            cipherMode = cip.DES.new(key, cip.DES.MODE_EAX, nonce=ivNonce)
            decryptedMsg = cipherMode.decrypt(msg)

    return decryptedMsg


def startConnection():
    message = receiveConn()
    cipher, ivNon, key, msg= readMessage(message)
    ivNonB = binascii.unhexlify(ivNon)
    keyB = binascii.unhexlify(key.encode())
    msgB = binascii.unhexlify(msg)

    msgDec = decryptMsg(cipher, keyB, ivNonB, msgB)
    print(msgDec.decode())

    if re.search("Blink", msgDec.decode()):
        loopTimes = msgDec.decode().split(":")[1]
        print("It will blink now " + str(int(loopTimes)) + " Times.")

        for x in range(int(loopTimes)):
            board.digital[13].write(1)
            time.sleep(1)
            board.digital[13].write(0)
        time.sleep(0.2)

def main(argv):

    if len(argv) != 1:
        sys.exit("Error. Invalid number of params.")
    else:
        startConnection()
        

if __name__ == '__main__':
    main(sys.argv[0:])
