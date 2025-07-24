# 
A client-server login and messaging architecture involving a centralized server that handles multiple
requests from a large client group based on the Confidentiality-Integrity-Authentication (CIA) concepts.

Included all the files

Client-server architecture, public and private keys:

•
The system consists of a client and a server Java program, and they must be named Client.java and Server.java respectively. They are started by running the commands
java Server port
java Client host port userid
specifying the hostname and port number of the server, and the userid of the client.

•
The server is a temporary store for all the messages sent by agents that are not yet read by their recipients. The server program is always running once started and listens for incoming connections at the port specified. When a client is connected, the server handles the request, then waits for the next request (i.e., the server never terminates). For simplicity, you
can assume that only one client will connect to the server at any one
time.

•
The secret agents are users of the client program. Each agent has a unique userid, which is a simple string like alice, bob etc. The server has userid "server". Each agent, as well as the server, is associated with a pair of RSA public and private keys, with filenames that have .pub or. prv after the userid, respectively. Thus, the key files are named alice.pub, server.prv, etc. These keys are generated separately by a program RSAKeyGen.java. More details are in the comments of that program.
•
It is assumed that the server already has its own private key and the public keys of all agents, and each agent already has their own private key as well as the public key of the server. They obtained these keys via some separate mechanism not described here, prior to the execution of the client and server programs, and is not part of these programs. The client and server programs never create any new keys or distribute them. Note that an agent does not have the public key of the other agents (e.g., alice does not have the public key of bob); in fact, they probably don't know the true identity of each other. The secret agency that they work for do not want them to have secret communications among themselves.