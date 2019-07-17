# PolicyManager

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

Encryption method  | 

IV used>/<Nonce used | 

Key used (Symmetric environment) |

Message content encrypted in the method above

---END OF MESSAGE FORMAT---


As stated above, the whole content of the message must be encrypted
using the server key that should be provided to you when you first use the system.

Author: Jose Maria Santos Lopez
University of Malaga
Final-Year Project (TFG)
v.1.0
