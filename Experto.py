from pyknow import *
import DataBase as db
from Gestor import Gestor
import binascii
'''
Expert system for our policy manager
Mainly focused in Symmetric cryptography
It chooses between elements stored in database
like: Type of node and Cryptography available

A is sender
B is receiver

Ciphers have to be saved as lists [ ]

Ciphers supported:
    -AES
    -AES_CBC
    -DES / DES_CBC
    -3DES / 3DES_CBC
    -RC5 ???
    -IDEA ???
    -Blowfish / Blowfish_CBC

Type of nodes:
    -P (Powerful) +
    -W (Weak) -
    -H (Highest Power) ++


It is given that the manager has the ability to use every cipher the nodes may use.
When the nodes can't connect via a common cipher, the manager may use one from the receiver,
transform the sent data and pass it to the objective node.
'''     

def isList(l):
    return isinstance(l, list)

class NodeA(Fact):
    pass

class NodeB(Fact):
    pass

class Message(Fact):
    pass


class RoleA(Fact):
    pass




class Manager(KnowledgeEngine):

    @staticmethod
    def checkCiphers(a, b, typenodeA, typenodeB, cipher_used):
        pair = False

        for cB in b(typenodeB).get(0)['cipher']:
            if (cB == cipher_used):
                pair = True

        return pair

    #Receiver > sender (the receiver can compute every input, as long as it has the proper cipher)
    @Rule(AS.typenodeA << NodeA(typenode = 'W'),
          AS.typenodeB << NodeB(typenode = 'P'), # B > A
          AS.message << Message(content = W())) 
    def typeBgAWP(self, typenodeA, typenodeB, message):
        cipher_used = Gestor.readMessage(Message(message).get(0)['content'])[0]
        pair = Manager.checkCiphers(NodeA,NodeB, typenodeA, typenodeB, cipher_used)
        idNodeA = NodeA(typenodeA).get(0)['idnode']
        idNodeB = NodeB(typenodeB).get(0)['idnode']
        if (pair != True):
            messageTransformed = self.makeChange(typenodeA, typenodeB, Message(message).get(0)['content'])
            Gestor.writeInFile(messageTransformed.decode('utf-8'))
            print("Your new message to send to " + idNodeB + " is: " + messageTransformed.decode('utf-8'))
        else:
            print("The message is valid for communication")
        #print(NodeB(typenodeB).as_dict().get(0)['cipher'])

        db.log(idNodeA, idNodeB)

    @Rule(AS.typenodeA << NodeA(typenode = 'W'),
          AS.typenodeB << NodeB(typenode = 'H'), # B > A
          AS.message << Message(content = W())) 
    def typeBgAWH(self, typenodeA, typenodeB, message):
        cipher_used = Gestor.readMessage(Message(message).get(0)['content'])[0]
        pair = Manager.checkCiphers(NodeA,NodeB, typenodeA, typenodeB, cipher_used)
        idNodeA = NodeA(typenodeA).get(0)['idnode']
        idNodeB = NodeB(typenodeB).get(0)['idnode']
        if (pair != True):
            messageTransformed = self.makeChange(typenodeA, typenodeB, Message(message).get(0)['content'])
            Gestor.writeInFile(messageTransformed.decode('utf-8'))
            print("Your new message to send to " + idNodeB + " is: " + messageTransformed.decode('utf-8'))
        else:
            print("The message is valid for communication")
        #print(NodeB(typenodeB).as_dict().get(0)['cipher'])

        db.log(idNodeA, idNodeB)

    @Rule(AS.typenodeA << NodeA(typenode = 'P'),
          AS.typenodeB << NodeB(typenode = 'H'), # B > A
          AS.message << Message(content = W())) 
    def typeBgAPH(self, typenodeA, typenodeB, message):
        cipher_used = Gestor.readMessage(Message(message).get(0)['content'])[0]
        pair = Manager.checkCiphers(NodeA,NodeB, typenodeA, typenodeB, cipher_used)
        idNodeA = NodeA(typenodeA).get(0)['idnode']
        idNodeB = NodeB(typenodeB).get(0)['idnode']
        if (pair != True):
            messageTransformed = self.makeChange(typenodeA, typenodeB, Message(message).get(0)['content'])
            Gestor.writeInFile(messageTransformed.decode('utf-8'))
            print("Your new message to send to " + idNodeB + " is: " + messageTransformed.decode('utf-8'))
        else:
            print("The message is valid for communication")
        #print(NodeB(typenodeB).as_dict().get(0)['cipher'])

        db.log(idNodeA, idNodeB)

    #Sender > Receiver
    @Rule(AS.typenodeA << NodeA(typenode = 'P'),
          AS.typenodeB << NodeB(typenode = 'W'),
          AS.message << Message(content = W())) # A > B
    def typeAgBPW(self, typenodeA, typenodeB, message):
        cipher_used = Gestor.readMessage(Message(message).get(0)['content'])[0]
        pair = Manager.checkCiphers(NodeA,NodeB, typenodeA, typenodeB, cipher_used)
        idNodeA = NodeA(typenodeA).get(0)['idnode']
        idNodeB = NodeB(typenodeB).get(0)['idnode']
        if (pair != True):
            messageTransformed = self.makeChange(typenodeA, typenodeB, Message(message).get(0)['content'])
            Gestor.writeInFile(messageTransformed.decode('utf-8'))
            print("Your new message to send to " + idNodeB + " is: " + messageTransformed.decode('utf-8'))
        else:
            print("The message is valid for communication")
            #print(NodeB(typenodeB).as_dict().get(0)['cipher'])

        db.log(idNodeA, idNodeB)


    #Sender > Receiver
    @Rule(AS.typenodeA << NodeA(typenode = 'H'),
          AS.typenodeB << NodeB(typenode = 'P'),
          AS.message << Message(content = W())) # A > B
    def typeAgBHP(self, typenodeA, typenodeB, message):
        cipher_used = Gestor.readMessage(Message(message).get(0)['content'])[0]
        pair = Manager.checkCiphers(NodeA,NodeB, typenodeA, typenodeB, cipher_used)
        idNodeA = NodeA(typenodeA).get(0)['idnode']
        idNodeB = NodeB(typenodeB).get(0)['idnode']
        if (pair != True):
            messageTransformed = self.makeChange(typenodeA, typenodeB, Message(message).get(0)['content'])
            Gestor.writeInFile(messageTransformed.decode('utf-8'))
            print("Your new message to send to " + idNodeB + " is: " + messageTransformed.decode('utf-8'))
        else:
            print("The message is valid for communication")
            #print(NodeB(typenodeB).as_dict().get(0)['cipher'])

        db.log(idNodeA, idNodeB)


    #Sender > Receiver
    @Rule(AS.typenodeA << NodeA(typenode = 'H'),
          AS.typenodeB << NodeB(typenode = 'W'),
          AS.message << Message(content = W())) # A > B
    def typeAgBHW(self, typenodeA, typenodeB, message):
        cipher_used = Gestor.readMessage(Message(message).get(0)['content'])[0]
        pair = Manager.checkCiphers(NodeA,NodeB, typenodeA, typenodeB, cipher_used)
        idNodeA = NodeA(typenodeA).get(0)['idnode']
        idNodeB = NodeB(typenodeB).get(0)['idnode']
        if (pair != True):
            messageTransformed = self.makeChange(typenodeA, typenodeB, Message(message).get(0)['content'])
            Gestor.writeInFile(messageTransformed.decode('utf-8'))
            print("Your new message to send to " + idNodeB + " is: " + messageTransformed.decode('utf-8'))
        else:
            print("The message is valid for communication")
            #print(NodeB(typenodeB).as_dict().get(0)['cipher'])

        db.log(idNodeA, idNodeB)


    #Sametype W
    @Rule(AS.typenodeA << NodeA(typenode = 'W'),
          AS.typenodeB << NodeB(typenode = 'W'),
          AS.message << Message(content = W()))
    def typeAeBW(self,typenodeA,typenodeB, message):
        cipher_used = Gestor.readMessage(Message(message).get(0)['content'])[0]
        pair = Manager.checkCiphers(NodeA,NodeB, typenodeA, typenodeB, cipher_used)
        idNodeA = NodeA(typenodeA).get(0)['idnode']
        idNodeB = NodeB(typenodeB).get(0)['idnode']
        if (pair != True):
            messageTransformed = self.makeChange(typenodeA, typenodeB, Message(message).get(0)['content'])
            Gestor.writeInFile(messageTransformed.decode('utf-8'))
            print("Your new message to send to " + idNodeB + " is: " + messageTransformed.decode('utf-8'))
        else:
            print('Connection is possible between: ' + idNodeA + ' & ' + idNodeB)

        db.log(idNodeA, idNodeB)


    #Sametype P
    @Rule(AS.typenodeA << NodeA(typenode = 'P'),
          AS.typenodeB << NodeB(typenode = 'P'),
          AS.message << Message(content = W()))
    def typeAeBP(self,typenodeA,typenodeB, message):
        cipher_used = Gestor.readMessage(Message(message).get(0)['content'])[0]
        pair = Manager.checkCiphers(NodeA,NodeB, typenodeA, typenodeB, cipher_used)
        idNodeA = NodeA(typenodeA).get(0)['idnode']
        idNodeB = NodeB(typenodeB).get(0)['idnode']
        if (pair != True):
            messageTransformed = self.makeChange(typenodeA, typenodeB, Message(message).get(0)['content'])
            Gestor.writeInFile(messageTransformed.decode('utf-8'))
            print("Your new message to send to " + idNodeB + " is: " + messageTransformed.decode('utf-8'))
        else:
            print('Connection is possible between: ' + idNodeA + ' & ' + idNodeB)

        db.log(idNodeA, idNodeB)




    #Sametype H
    @Rule(AS.typenodeA << NodeA(typenode = 'H'),
          AS.typenodeB << NodeB(typenode = 'H'),
          AS.message << Message(content = W()))
    def typeAeBH(self,typenodeA,typenodeB, message):
        cipher_used = Gestor.readMessage(Message(message).get(0)['content'])[0]
        pair = Manager.checkCiphers(NodeA,NodeB, typenodeA, typenodeB, cipher_used)
        idNodeA = NodeA(typenodeA).get(0)['idnode']
        idNodeB = NodeB(typenodeB).get(0)['idnode']
        if (pair != True):
            messageTransformed = self.makeChange(typenodeA, typenodeB, Message(message).get(0)['content'])
            print("Your new message to send to " + idNodeB + " is: ")
            Gestor.writeInFile(messageTransformed.decode('utf-8'))
            print(messageTransformed.decode('utf-8'))
        else: # binascii.hexlify(messageTransformed).decode('utf-8')
            print('Connection is possible between: ' + idNodeA + ' & ' + idNodeB)

        db.log(idNodeA, idNodeB)


    def makeChange(self, typenodeA, typenodeB, message):
        ciphers_receiver = NodeB(typenodeB).get(0)['cipher']
        cipher_to_use = next(iter(ciphers_receiver))
        receiver = NodeB(typenodeB).get(0)['idnode'] #Receiver of the ECC message
        messageTransformed = Gestor.transformMessageTo(message, cipher_to_use, receiver)
        return messageTransformed
        #In DB, we may store the symmetric key to send to receiver

        #Transform the message from A cipher to B selected cipher
        #We may store the cipher used in a hash format, so the manager can read it.
        #The first line of the message must be the hashed cipher
        #If the cipher needs some IV, the second line should be the IV hashed/encrypted
        #We could use the Gestor class to separate the hash from the message


class Roles(KnowledgeEngine):

    @Rule(AS.roleA << RoleA(role = 'Eng'))
    def engOptions(self, roleA):
        engMsg = '''     
        As an Engineer of the system, you may use this options:
            1. Print the state of the log.
            2. Use the policy manager with the given message.
            3. Generate new keypair.
            4. Exit the application.
        '''
        idnode = RoleA(roleA).get(0)['idnode']
        print(engMsg)
        option = input()
        Gestor.engOptions(option,idnode)

        #print(NodeB(typenodeB).as_dict().get(0)['cipher'])

    @Rule(AS.roleA << RoleA(role = 'Node'))
    def nodeOptions(self, roleA):
        nodeMsg = '''     
        As a normal user of the system, you may use this options:
            1. Use the policy manager with the given message.
            2. Generate new keypair.
            3. Exit the application.
        '''
        idnode = RoleA(roleA).get(0)['idnode']
        print(nodeMsg)
        option = input()
        Gestor.nodeOptions(option, idnode)

    @Rule(AS.roleA << RoleA(role = 'Admin'))
    def adminOptions(self, roleA):
        adminMsg = '''     
        As an Admin of the system, you may use this options:
            1. Print the state of the Log.
            2. Print the state of the Database.
            3. Use the policy manager with the given message.
            4. Generate new keypair (Includes a DB backup).
            5. Insert a new user
            6. Delete a named user.
            7. Exit the application.
        '''
        idnode = RoleA(roleA).get(0)['idnode']
        print(adminMsg)
        option = input()
        Gestor.adminOptions(option,idnode)

'''
getFromDB:
    dbnodes : List of Nodes to find in the db
    As there always will be a connection between 2 nodes, the list must contain 2 values.
    If there would be any improvement to the Manager, this number may be increased.
    The first value in the list must be the first node, and this should be A.

    In "Gestor" when a node wants to use this system, it should provide the objective node,
    so it can be stored into the database
'''
def getFromDB(dbnodes, message, engine):
    nodes = db.connection()
    for idn in dbnodes:
        try:
            node = nodes.find_one({"ID" : idn})
            if idn == dbnodes[0]:
                engine.declare(NodeA(idnode = node["ID"], typenode = node["Type"], ciper = node["Cipher"], role = node["Role"]))
            else:
                engine.declare(NodeB(idnode = node["ID"], typenode = node["Type"], ciper = node["Cipher"], role = node["Role"]))
        except:
            print("Error. Node " + idn + " Is not in database." )
    
    engine.declare(Message(content = message))

    return engine


def getFromDBRoles(name, engine):
    nodes = db.connection()
    try:
        node = nodes.find_one({"ID" : name})
        engine.declare(RoleA(idnode = node["ID"], typenode = node["Type"], ciper = node["Cipher"], role = node["Role"]))
    except:
        print("Error. Node " + name + " Is not in database." )

    return engine


def runManager(dbnodes, message):
    engineManager = Manager()
    engineManager.reset()

    nodes = db.connection()
    for idn in dbnodes:
    #try:
        node = nodes.find_one({"ID" : idn})
        if idn == dbnodes[0]:
            engineManager.declare(NodeA(idnode = node["ID"], typenode = Gestor.decryptData(node["Type"]), cipher = Gestor.decryptList(node["Cipher"]), role = Gestor.decryptData(node["Role"])))
        else:
            engineManager.declare(NodeB(idnode = node["ID"], typenode = Gestor.decryptData(node["Type"]), cipher = Gestor.decryptList(node["Cipher"]), role = Gestor.decryptData(node["Role"])))
    #except:
        #print("Error. Node " + idn + " Is not in database." )

    engineManager.declare(Message(content = message))
    engineManager.run()



def runRoles(name):
    engineRoles = Roles()
    engineRoles.reset()

    nodes = db.connection()
#try:
    node = nodes.find_one({"ID" : name})
    engineRoles.declare(RoleA(idnode = node["ID"], typenode = Gestor.decryptData(node["Type"]), cipher = Gestor.decryptList(node["Cipher"]), role = Gestor.decryptData(node["Role"])))
    engineRoles.run()
#except:
    #print("Error. Nodes " + name + " Is not in database." )
    #engine = getFromDBRoles(node, engine)

    #engine.run()
