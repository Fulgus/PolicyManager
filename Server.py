import socket
import sys
import re

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "192.168.0.27"
port = 2007
soc.bind((host, port))
soc.listen(1)


conn, addr = soc.accept()

print("Got connection from",addr)
length_of_message = int.from_bytes(conn.recv(4), byteorder=sys.byteorder)
msg = conn.recv(length_of_message).decode("UTF-8")

filewrite = open("Received.txt", "w")
filewrite.write(msg)
print(msg)

#En esta fase se inicia el gestor

wait = input("Iniciamos el gestor.")

file = open("msg.txt", "rt")
message = file.read()

conn.sendall((message + "\n").encode())

length_of_end = int.from_bytes(conn.recv(4), byteorder=sys.byteorder)
endmsg = conn.recv(length_of_message).decode("UTF-8")

if re.search("ENDMSG", endmsg):
    soc.close
    print("Message closed.")
    sys.exit()
    
