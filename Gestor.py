import Cryptodome.Cipher as cip
from Cryptodome.Cipher import AES,DES,DES3,Blowfish
import Experto
import re


#ECDH MIT license
from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt


import cpuinfo as cpu
import os
import sys
import socket


import base64
import binascii #For passgeneration
import hashlib, uuid #For hashing + salting
import DataBase as db
from datetime import datetime as time


def getSysInput():
    '''
    Reads system input from main execution and returns its values

    '''
    dbnodes = sys.argv[1:3]
    file = open(sys.argv[3], "rt")
    message = file.read()
    #message = sys.argv[3]
    file.close()
    return dbnodes, message

class Gestor:

    def __init__(self):
        print("PM opened.")

    @staticmethod
    def generatePassword(size):
        '''
        Generates a new password.
        This password could be used for rekeygen purposes.

        Returns
        -------

        Passbytes : bytes

            Bytes version of password.

        Password : String

            UTF-8 decoded value of the hex String that is generated.
        
        ''' 
        passbytes = os.urandom(size)
        password = binascii.hexlify(passbytes)
        return passbytes, password.decode('utf-8')
    

    @staticmethod
    def generateKeyPair():
        '''
        Generates private and public key pair for key exchange

        '''
        session_key = generate_key()
        private_key = session_key.to_hex()
        public_key = session_key.public_key.format(True).hex()
        return private_key, public_key

    @staticmethod
    def generateHashSalted(password):
        '''
        Hashes a given password adding a created salt to it.

        Returns
        -------

        Salt : String

            Hex string of the salt generated.

        PassHash : String
            
            Hex string of the password + salt hash
        
        ''' 
        salt = uuid.uuid4().hex
        passhash = hashlib.sha512((password + salt).encode('utf-8')).hexdigest()
        return salt, passhash

    @staticmethod
    def registerUser(name, type, cipher, password, role):
        '''
        Register a new Node to the database.
    
        Parameters
        ----------

        Name : String
            
            Name of the node to register.

        Type : String

            Type of node. Must be "W", "P", or "H". 

        Cipher : List
        
            List of supported ciphers by the node.

        Password : String

            Access password that will be used for the node to log in.
        
        ''' 
        BD = db.connection()
        salt, passhash = Gestor.generateHashSalted(password)
        try:
            priv_key, pub_key = Gestor.generateKeyPair()
            BD.insert_one({"_id" : str(BD.count_documents({})+1), "ID" : name, "Type" : Gestor.encryptData(type), "Cipher" : Gestor.encryptList(cipher), "LastAccPwdUpdate" : time.now().strftime("%d-%m-%Y"), "Password" : passhash, "Salt" : salt, "Role" : Gestor.encryptData(role)})
            print("user: " + name + " is now registered." + "\n")

            print('Access password is: ' + password + "\n" + 'Please, make sure you remember it.')
            print('Your private key generated for this system is: ' + priv_key)
            db.updateKeys(pub_key, name)
        except:
            print("An error occurred while inserting")


    @staticmethod
    def encryptData(data):
        '''
        Encrypt DB data

        '''
        BD = db.connectionKeys()

        public_server_key = BD.find_one({"ID" : "Server"})["PubKey"]
        dataBytes = data.encode()
        encData = encrypt(public_server_key, dataBytes)

        return binascii.hexlify(encData).decode()

    @staticmethod
    def encryptList(data):
        '''
        Encrypt List
        '''
        if type(data) is str:
            data = list(data.split(","))
        encList = []
        BD = db.connectionKeys()

        public_server_key = BD.find_one({"ID" : "Server"})["PubKey"]
        
        for item in data:
            itemBytes = item.encode()
            encItem = encrypt(public_server_key, itemBytes)
            encList.append(binascii.hexlify(encItem).decode())
        return encList




    @staticmethod
    def decryptList(data):
        '''
        Decrypt List
        '''
        decList = []
    
        BD = db.connectionKeys()

        private_server_key = BD.find_one({"ID" : "Server"})["PrivKey"]

        for item in data:
            itemBytes = binascii.unhexlify(item.encode())
            decItem = decrypt(private_server_key, itemBytes)
            decList.append(decItem.decode())

        return decList


    @staticmethod
    def decryptData(data):
        '''
        Decrypt DB data
        '''
        BD = db.connectionKeys()

        private_server_key = BD.find_one({"ID" : "Server"})["PrivKey"]

        dataBytes = binascii.unhexlify(data.encode())
        decData = decrypt(private_server_key, dataBytes)
        return decData.decode()


    @staticmethod
    def checkPassword(user, password):
        '''
        Checks if a given pair of username/password is in the database and 
        is correct.

        Parameters
        ----------
        user : String 

            node username

        password : String

            Access password of the node

        Returns
        -------

        Status : String
            Status of the operation. It can be "ok", "pwd" and "usr"
                "ok" - No errors
                "pwd" - Password is not correct.
                "usr" - User is not found.
        Correct : boolean
            Value of the password check itself. True if it is correct, False otherwise.

        
        ''' 
        node = Gestor.checkUser(user)
        if node is not None:  
            passHashed = node["Password"]
            salt = node["Salt"]
            passToCheck = hashlib.sha512((password + salt).encode('utf-8')).hexdigest()
            if passToCheck == passHashed:
                return "ok", True
            else:
                return "pwd", False
        else:
            print("User not found")
            return "usr", False
        

    #Auxiliar
    @staticmethod
    def daysBetween(d1, d2):
        '''
            Calculates the days between two given dates, d1 and d2.

            Parameters
            ----------

            d1 : Date
            d2 : Date

        '''

        date1 = time.strptime(d1, "%d-%m-%Y")
        date2 = time.strptime(d2, "%d-%m-%Y")
        return abs((date2 - date1).days)

    @staticmethod
    def checkPwdExpiryDate(user):
        '''
        Checks if the stored password has expired

        Parameters
        ----------

        User : String

            The username to check.

        '''

        BD = db.connection()
        try:
            node = BD.find_one({"ID" : user})
            lastDate = node["LastAccPwdUpdate"]
            days = Gestor.daysBetween(lastDate, str(time.now().date().strftime("%d-%m-%Y")))

            if days > 365: #Source: NIST
                print('You have to change your password.')
                print('Your new password is:')
                passbytes, password = Gestor.generatePassword(8)
                print(password+'')
                salt, passhash = Gestor.generateHashSalted(password)
                db.updatePassword(password, salt, user)
                input()
        except:
            print('An error occurred. Node not found.')



    @staticmethod
    def checkUser(user):
        '''
        Checks if a given username is stored in the database

        Parameters
        ----------

        User : String

            The username to check.

        ''' 

        BD = db.connection()
        try:
            node = BD.find_one({"ID" : user})
            return node
        except:
            return None

    #NotUsed
    @staticmethod
    def checkType(user):
        '''
        Gets the type of the given node.
        ''' 
        node = Gestor.checkUser(user)
        if node is not None:
            return node["Type"]
        else:
            return "failed"

    @staticmethod
    def adminOptions(option,idnode):
        '''
        Sets different options for a given admin user

        Parameters
        ----------

        option : String

            The chosen option.

        idnode : String

            Username

        '''
        if option is "1":
            db.dumpLog()
        else:
            if option is "2":
                db.dumpNodes()
            else:
                if option is "3":
                    dbnodes, message = getSysInput()
                    Experto.runManager(dbnodes, message)
                else:
                    if option is "4":
                        priv, pub = Gestor.generateKeyPair()
                        print("Server--- private: " + priv + "\n" + "public: " + pub)
                        privAd, pubAd = Gestor.generateKeyPair()
                        print("Admin--- private: " + privAd + "\n" + "public: " + pubAd)
                        db.updateKeys(pubAd, idnode)
                        db.backupAndRestore(priv, pub)
                    else:
                        if option is "5":
                            print("Insert these parameters: ")
                            name = input("Name: ")
                            type = input("Type: ")
                            cipher = input("Cipher: (as List [ ])")
                            role = input("Role: ")
                            passbytes, password = Gestor.generatePassword(8) 
                            privKey, pubKey = Gestor.generateKeyPair()     
                            salt, passhash = Gestor.generateHashSalted(password)
                            print("Please inform given user that its new password and private Key are: ")
                            print("pwd: " + password)
                            print("privkey: " + privKey)
                            db.insertUser(name, type, cipher, passhash, salt, role, pubKey)
                        else:
                            if option is "6":
                                print("Insert the name of the node to delete: ")
                                name = input("Name: ")
                                db.deleteNode(name)
                            else:
                                sys.exit()


    @staticmethod
    def nodeOptions(option,idnode):
        '''
        Sets different options for a given normal user

        Parameters
        ----------

        option : String

            The chosen option.

        idnode : String

            Username

        '''
        if option is "1":
            dbnodes, message = getSysInput()
            Experto.runManager(dbnodes, message)
        else:
            if option is "2":
                priv, pub = Gestor.generateKeyPair()
                print("private: " + priv + "\n" + "public: " + pub)
                db.updateKeys(pub, idnode)
            else:
                sys.exit()


    @staticmethod
    def engOptions(option,idnode):
        '''
        Sets different options for a given engineer user

        Parameters
        ----------

        option : String

            The chosen option.

        idnode : String

            Username

        '''
        if option is "1":
            db.dumpLog()
        else:
            if option is "2":
                dbnodes, message = getSysInput()
                Experto.runManager(dbnodes, message)
            else:
                if option is "3":
                    priv, pub = Gestor.generateKeyPair()
                    print("private: " + priv + "\n" + "public: " + pub)
                    db.updateKeys(pub, idnode)
                else:
                    sys.exit()

    @staticmethod
    def initConnection():
        '''
        Starts the connection with the system, asking for node credentials.

        ''' 

        print('---Login---')
        print('Insert your nodeName: ')
        name = sys.argv[1]

        print('Nodename: ' + name)
        if Gestor.checkUser(name) is not None:
            print('Insert password of ' + name + ':')
            password = input()
            value, correct = Gestor.checkPassword(name, password)

            while value == "pwd":
                print('Incorrect password')
                print('Please, insert password: ')
                password = input()
                value, correct = Gestor.checkPassword(name, password)

            print('Correct password')
            Gestor.checkPwdExpiryDate(name)

        else:
            Gestor.registerWindow(name)
            sys.exit()

        Experto.runRoles(name)

    @staticmethod
    def registerWindow(nodeName):
        '''
        Selects some node variables (Type and Cipher)
        depending on its capability.

        Parameters
        ----------

        nodeName : String

            The node to register.

        ''' 

        power = cpu.get_cpu_info()['hz_advertised'].split(' ')[0]
        passbytes, password = Gestor.generatePassword(8)
        if float(power) > 1.65 and float(power) < 3.00: #Medium power, P
            nodeType = 'P'
            cipher = ['AES', 'AES-CBC', 'DES', 'DES-CBC', '3DES', 'Blowfish']
        if float(power) < 1.65: #Low power, W
            nodeType = 'W'
            cipher = ['Blowfish', 'DES', 'AES']
        else:                   #Highest power, H
            nodeType = 'H'
            cipher = ['AES', 'AES-CBC', 'DES', 'DES-CBC', '3DES', 'DES3-CBC', 'Blowfish', 'Blowfish-CBC' ,'IDEA', 'RC5']


        print('Please, input your role: (Eng, Node)') #Admin role is assigned directly to database
        role = input()
        Gestor.registerUser(nodeName, nodeType, cipher, password, role)
    
    @staticmethod
    def generateIV(size):
        '''
            Returns a bytes object of given size, to be used as Nonce or IV

        '''
        return os.urandom(size)

    @staticmethod
    def dataExchangeECC(target_node, data):
        '''
            Takes a target node and sends a key to be used in further connections
            with its designated objective node.

            This is all performed in an ECC environment, where all parties have
            (or should have) their personal key pair suitable for this actions.

            Parameters
            ----------

            target_node : String

                Node to which the symmetric key will be sent.

            size: int 

                Number of bytes to create the symmetric password.

        '''

        BD = db.connectionKeys()

        public_key = BD.find_one({"ID" : target_node})["PubKey"]
        private_server_key = BD.find_one({"ID" : "Server"})["PrivKey"]
        message = data.encode()
        encMsg = encrypt(public_key, message)

        return binascii.hexlify(encMsg)
        
    @staticmethod
    def signatureECC(msg, target_node):
        BD = db.connectionKeys()
        node_pubKey = BD.find_one({"ID" : target_node})["PubKey"] #Ciphers the hash of the message to check integrity
        msgHashed = hashlib.sha512(msg.encode()).hexdigest()
        encMsg = encrypt(node_pubKey, msgHashed.encode())

        return binascii.hexlify(encMsg)

    @staticmethod
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
        if re.search("AES" ,cipher_used):
            if re.search("CBC", cipher_used):
                cipherMode = cip.AES.new(key, cip.AES.MODE_CBC, iv=ivNonce)
                decryptedMsg = cipherMode.decrypt(msg)
            else:
                cipherMode = cip.AES.new(key, cip.AES.MODE_EAX, nonce=ivNonce)
                decryptedMsg = cipherMode.decrypt(msg)

        if re.search("^DES" ,cipher_used):
            if re.search("CBC", cipher_used):
                cipherMode = cip.DES.new(key, cip.DES.MODE_CBC, iv=ivNonce)
                decryptedMsg = cipherMode.decrypt(msg)
            else:
                cipherMode = cip.DES.new(key, cip.DES.MODE_EAX, nonce=ivNonce)
                decryptedMsg = cipherMode.decrypt(msg)

        if re.search("^3DES" ,cipher_used):
            if re.search("CBC", cipher_used):
                cipherMode = cip.DES3.new(key, cip.DES3.MODE_CBC, iv=ivNonce)
                decryptedMsg = cipherMode.decrypt(msg)
            else:
                cipherMode = cip.DES3.new(key, cip.DES3.MODE_EAX)
                decryptedMsg = cipherMode.decrypt(msg)

        if re.search("Blowfish" ,cipher_used):
            if re.search("CBC", cipher_used):
                cipherMode = cip.Blowfish.new(key, cip.Blowfish.MODE_CBC, iv=ivNonce)
                decryptedMsg = cipherMode.decrypt(msg)
            else:
                cipherMode = cip.Blowfish.new(key, cip.Blowfish.MODE_EAX, nonce=ivNonce)
                decryptedMsg = cipherMode.decrypt(msg)

        return decryptedMsg


    @staticmethod
    def encryptMsg(cipher_to_use, key_to_use, newIvNonce, msg_to_encrypt):
        '''
        Gets a given message and certain parameters to encrypt it.

        Parameters
        ----------

        cipher_to_use : String

            The cipher to be encrypted with.

        key_to_use : bytes object

            Key to be used in encryption.

        newIvNonce : bytes object

            IV or Nonce to be used, according to cipher to use.

        msg_to_encrypt : bytes object

            Plain text message to encrypt.

        '''
        newKey = key_to_use
        msg = msg_to_encrypt

        if re.search("AES" ,cipher_to_use):
            if re.search("CBC", cipher_to_use):
                cipherMode = cip.AES.new(newKey, cip.AES.MODE_CBC, iv=newIvNonce)
                encryptedMsg = cipherMode.encrypt(msg)
            else:
                cipherMode = cip.AES.new(newKey, cip.AES.MODE_EAX, nonce=newIvNonce)
                encryptedMsg = cipherMode.encrypt(msg)

        if re.search("^DES" ,cipher_to_use):
            if re.search("CBC", cipher_to_use):
                cipherMode = cip.DES.new(newKey, cip.DES.MODE_CBC, iv=newIvNonce)
                encryptedMsg = cipherMode.encrypt(msg)
            else:
                cipherMode = cip.DES.new(newKey, cip.DES.MODE_EAX, nonce=newIvNonce)
                encryptedMsg = cipherMode.encrypt(msg)

        if re.search("^3DES" ,cipher_to_use):
            if re.search("CBC", cipher_to_use):
                cipherMode = cip.DES3.new(newKey, cip.DES3.MODE_CBC, iv=newIvNonce)
                encryptedMsg = cipherMode.encrypt(msg)
            else:
                cipherMode = cip.DES3.new(newKey, cip.DES3.MODE_EAX, nonce=newIvNonce)
                encryptedMsg = cipherMode.encrypt(msg)

        if re.search("Blowfish" ,cipher_to_use):
            if re.search("CBC", cipher_to_use):
                cipherMode = cip.Blowfish.new(newKey, cip.Blowfish.MODE_CBC, iv=newIvNonce)
                encryptedMsg = cipherMode.encrypt(msg)
            else:
                cipherMode = cip.Blowfish.new(newKey, cip.Blowfish.MODE_EAX, nonce=newIvNonce)
                encryptedMsg = cipherMode.encrypt(msg)

        return encryptedMsg


    @staticmethod
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
        keys = db.connectionKeys()
        sysPrivKey = keys.find_one({"ID" : "Server"})["PrivKey"]
        try:
            decryptedMsgBytes = decrypt(sysPrivKey, binascii.unhexlify(message.strip().encode()))
            decryptedMsg = decryptedMsgBytes.decode('utf-8')
            linesMsg = decryptedMsg.split('|')
            cipher_used = linesMsg[0]
            ivNonce = linesMsg[1]
            key = linesMsg[2]
            msg = linesMsg[3]

        except:
            print("Message is not encrypted in Public Key of server. Please change it.")
            sys.exit()

        return cipher_used, ivNonce, key, msg



    @staticmethod
    def decryptEncryptTo(msg, cipher_used, ivNonce, key, cipher_to_use, newKey, newIvNonce):
        '''
        Uses decryptMsg and encryptMsg to transform the encryption into a new given cipher

        Parameters
        ----------

        msg : bytes object

            Message to transform.

        cipher_used : String

            The used cipher in encryption.

        key_used : bytes object

            Key used in decryption.

        ivNonce : bytes object

            IV or Nonce used, according to cipher used.
        
        cipher_to_use : String

            The cipher to be encrypted with.

        newKey : bytes object

            Key to be used in encryption.

        newIvNonce : bytes object

            IV or Nonce to be used, according to cipher to use.

        '''
        decryptedMsg = Gestor.decryptMsg(cipher_used, key, ivNonce, msg)
        encryptedMsg = Gestor.encryptMsg(cipher_to_use, newKey, newIvNonce, decryptedMsg)

        return encryptedMsg


    @staticmethod
    def getKeySize(cipher):
        '''
        Uses a given cipher to return its needed size for key and IV/Nonce

        Parameters
        ----------

        cipher : String

            The given cipher.

        '''
        if re.search("AES", cipher):
            keySize = 32
            ivSize = 16
        if re.search("DES", cipher):
            keySize = 8
            ivSize = 8
        if re.search("Blowfish", cipher):
            keySize = 32
            ivSize = 8

        return keySize, ivSize

    @staticmethod
    def transformMessageTo(message, cipher_to_use, receiver):
        '''
        Takes a message, parse its parameters and changes it to a new cipher.

        Parameters
        ----------

        message : String

            The message to parse from.

        cipher_to_use : String

            The cipher to encrypt the message to.

        receiver :

            Node who will receive the message. It will usually be the sender node,
            so it will be finally sending the message to the receiver node.

        '''
        cipher_used, ivNonce, key, msg = Gestor.readMessage(message)
        keySize, ivSize = Gestor.getKeySize(cipher_to_use)
        newKeyBytes, newKey = Gestor.generatePassword(keySize)
        newIvNonce = Gestor.generateIV(ivSize)

        keyB = binascii.unhexlify(key.encode())
        ivNonceB = binascii.unhexlify(ivNonce)
        msgB = binascii.unhexlify(msg)

        encMsg = Gestor.decryptEncryptTo(msgB, cipher_used, ivNonceB, keyB, cipher_to_use, newKeyBytes, newIvNonce)
        newMsg = Gestor.createNewMessage(encMsg, cipher_to_use, newKey, newIvNonce, receiver)

        return newMsg

    @staticmethod
    def createNewMessage(encMsg, cipher_to_use, newKey, ivNonce, receiver):
        '''
        Takes an encrypted message and transforms it into a valid, usable message
        for the system.

        Parameters
        ----------
        encMsg : bytes object

            Message the receiver will finally read.

        cipher_to_use : String
        
            Cipher used in the encrypted message.

        newKey : bytes object

            Key used in the encrypted message.

        ivNonce : bytes object

            IV/Nonce used in the encrypted message. It will depend on the cipher used.

        receiver : String

            The node who will receive the ECC encrypted message. It will usually be the sender
            so it will send it later to the receiver, or B node.

        '''
        ivNonce = binascii.hexlify(ivNonce).decode()
        encMsg = binascii.hexlify(encMsg).decode()
        msgHashed = Gestor.signatureECC(encMsg, receiver).decode()
        message = cipher_to_use + '|' + ivNonce + '|' + str(newKey) + '|' + encMsg + '|' + msgHashed
        newMsg = Gestor.dataExchangeECC(receiver, message)
        return newMsg

    @staticmethod
    def writeInFile(msg):
        '''
            Writes the content of msg into a file.
        '''
        file = open("msg.txt", "w")
        file.write(msg)
        file.close()



def main(argv):
    if len(argv) > 1 and argv[1] == '-h':
        helpMsg = """
Welcome to Policy Manager:

The usage of this program is by
entering 4 or 3 parameters (including main.py):

main.py <NodeA> <NodeB> <Message>

Where:

    NodeA : Source node name        - Sender - 
    NodeB : Destiny node            - Receiver-
    Message : Communication message - Object -  

    If you are using this program for the first time,
    you will be registered.

    If the system is "pseudo" automated, the first param (NodeA),
    could be optional. Not for now.

The message is encouraged to be encrypted, so the system
will be as safe as possible.

The way of encrypting the message is by using the server key
that is provided by the system, so all contents of the message
are protected in all channels.

The message must be of an specific format.

---MESSAGE FORMAT---

<Encryption method>  | 

<IV used>/<Nonce used> | 

<Key used> (Symmetric environment) |

<Message content encrypted in the method above>

---END OF MESSAGE FORMAT---

Note: each tagged value must be separated by "|" as delimiter.
For data compatibility, it is encouraged that "|" is escaped by the
escaping operator "\".

As stated above, the whole content of the message must be encrypted
using the server key that should be provided to you when you first use the system.

Author: Jose Maria Santos Lopez
University of Malaga
Final-Year Project (TFG)
v.1.0
        """
        print(helpMsg)
    else:
        if len(argv) != 4:
            print('Please, enter the correct number of parameters.\nUse -h option for further help.' )
            sys.exit("Error. Invalid number of params.")
        else:
            g = Gestor()
            g.initConnection()

if __name__ == '__main__':
    main(sys.argv[0:])
