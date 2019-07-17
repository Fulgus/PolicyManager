import pymongo
from datetime import datetime as time


def connection():
    '''
        Sets up a connection with the Nodes collection in our database.
    '''

    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["Gestor"] #Connect to Gestor db (TFG)
    nodes = db["Nodes"]
    return nodes

def connectionKeys():
    '''
        Sets up a connection with the PubKeys collection in our database.
    '''

    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["Gestor"] #Connect to Gestor db (TFG)
    keys = db["PubKeys"]
    return keys
    

def connectionLog():
    '''
        Sets up a connection with the Log collection in our database.
    '''

    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["Gestor"] #Connect to Gestor db (TFG)
    log = db["Log"]
    return log

    
def updateKeys(pubkey, idnode, privkey = None):
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["Gestor"]
    keys = db["PubKeys"]
    user = keys.find_one({"ID" : idnode})

    if privkey is not None:
        user = keys.find_one({"ID" : "Server"})
        user["PubKey"] = pubkey
        user["PrivKey"] = privkey
        keys.replace_one({"ID" : "Server"}, user)
        
    else:
        if user is not None:
            user["PubKey"] = pubkey
            keys.replace_one({"ID" : idnode}, user)
        else:
            keys.insert_one({"_id" : str(keys.count_documents({})+1), "ID" : idnode, "PubKey" : pubkey})


    


def updatePassword(password, salt, idnode):
        client = pymongo.MongoClient("mongodb://localhost:27017/")
        db = client["Gestor"]
        nodes = db["Nodes"]
        user = nodes.find_one({"ID" : idnode})

        if user is not None:
                user["Password"] = password
                user["Salt"] = salt
                nodes.replace_one({"ID" : idnode}, user)




def log(nodeA, nodeB):
    logs = connectionLog()
    logs.insert_one({"_id" : str(logs.count_documents({})+1), "Sender" : nodeA, "Receiver" : nodeB, "Date" : time.now().strftime("%d-%m-%Y")})

def dumpNodes():
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["Gestor"] #Connect to Gestor db (TFG)
    nodes = db["Nodes"]
    cursor = nodes.find()

    for node in cursor:
        print("{" + "_id: " +  node["_id"] + ", "  + "ID: " + " " + node["ID"] + ", "  + "Type: " + " "  + Gestor.decryptData(node["Type"]) + ", "  + "\nCipher: " ) 
        print(Gestor.decryptList(node["Cipher"]))
        print(", " + "LastAccPwdUpdate: " +  time.now().strftime("%d-%m-%Y") + ", " + "Password: " + node["Password"] + ", " + "Salt: " + node["Salt"] + ", " + "Role: " +  Gestor.decryptData(node["Role"]) + "}")


def dumpLog():
    client = pymongo.MongoClient("mongodb://localhost:27017/")
    db = client["Gestor"] #Connect to Gestor db (TFG)
    log = db["Log"]
    cursor = log.find()
    for value in cursor:
        print(value)

def insertUser(name, type, cipher, password, salt, role, pub_key):
    users = connection()
    keys = connectionKeys()
    users.insert_one({"_id" : str(users.count_documents({})+1), "ID" : name, "Type" : Gestor.encryptData(type), "Cipher" : Gestor.encryptList(cipher), "LastAccPwdUpdate" : time.now().strftime("%d-%m-%Y"), "Password" : password, "Salt" : salt, "Role" : Gestor.encryptData(role)})
    keys.insert_one({"_id" : str(keys.count_documents({})+1), "ID" : name, "PubKey" : pub_key})


def deleteNode(name):
        nodes = connection()
        nodes.delete_one({"ID" : name})

def getUser(name):
    return connection().find_one({"ID" : name})

from Gestor import Gestor
def backupAndRestore(priv, pub):
        client = pymongo.MongoClient("mongodb://localhost:27017/")
        db = client["Gestor"]
        nodesTable = db["Nodes"]
        keys = db["PubKeys"]
        backupTable = db["Backup"]
        pubKey = keys.find_one({"ID" : "Server"})["PubKey"]
        privKey = keys.find_one({"ID" : "Server"})["PrivKey"]
        
        nodes = nodesTable.find()
        for node in nodes:
                backupTable.insert_one({"_id" : node["_id"], "ID" : node["ID"], "Type" : Gestor.decryptData(node["Type"]), "Cipher" : Gestor.decryptList(node["Cipher"]), "LastAccPwdUpdate" : time.now().strftime("%d-%m-%Y"), "Password" : node["Password"], "Salt" : node["Salt"], "Role" : Gestor.decryptData(node["Role"])})
                print("Node backup: ")
                print(node)
                nodesTable.delete_one({"_id": node["_id"]})

        nodesBackup = backupTable.find()
        updateKeys(pub, "Server", priv)

        for node in nodesBackup:
                nodesTable.insert_one({"_id" : node["_id"], "ID" : node["ID"], "Type" : Gestor.encryptData(node["Type"]), "Cipher" : Gestor.encryptList(node["Cipher"]), "LastAccPwdUpdate" : time.now().strftime("%d-%m-%Y"), "Password" : node["Password"], "Salt" : node["Salt"], "Role" : Gestor.encryptData(node["Role"])})
                print("Node restored: ")
                print(node)
                backupTable.delete_one({"_id" : node["_id"]})

#node_to_insert = {"_id" : identifier, 
#                   "ID" : name, 
#                   "Type" : type, 
#                   "Cipher" : cipher, 
#                   "LastAccPwdUpdate" : time.now().strftime("%d-%m-%Y"), 
#                   "Password" : passhash, 
#                   "Salt" : salt, 
#                   "Role" : between -- [Engineer, User, Admin]}


# keys = {"_id" : identifier,
#         "ID" : name,
#         "PubKey" : key
#     }

# keys (server) = {"_id" : identifier,
#                 "ID" : "Server",
#                 "Key" : key}

#logs = {"_transaction_id" : identifier,
#        "Sender" : nameNodeA,
#        "Receiver" : nameNodeB,
#        "Date_of_Issue" : time.now().strftime("%d-%m-%Y")}             #Only store the participants to improve security
#nodes.insert_one(node_to_insert)