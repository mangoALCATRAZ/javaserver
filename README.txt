Matthew Angelucci
Lab - 6

THis is a complete working PKI-Based authentication protocol written in Java 8 on the Eclipse Java IDE. 

It comes in the form of 4 executables:
1. CA_Server_Exe to launch the Certificate Authority server.
2. S_Server_Exe to launch the main server S that will communicate with Client C
3. C_Client_Exe to launch the client server C
4. RSAKeyGen, which takes in a foldername and produces a set of public or private keys serialized to a .ser file
	to be then read back in by RSA_Obj's methods.

How to use:
------------------------------------
It is recommened that Java 8 be installed and Eclipse Java IDE be used to build and test.

1. Build and Launch all three Server executables, CA_Server_Exe, S_Server_Exe and C_Server_Exe
2. In CA_Server_Exe and S_Server_Exe, a menu will present itself. Set one server to join by entering
	command "join", and leave the other as host by default.
3. In CA_Server_Exe and S_Server_Exe, type in command "connect". For the one you set to join, enter the IP address
	of the other server without the port number. Usually its "localhost"
4. CA_Server and S_Server will now do the exchanges outlined in Steps 1 and 2. 
5. When this is finished CA_Server will finish executing, and S_Server will attempt to connect to C_server.
	Once again, it will ask for host/join. Set one server to host and the other to join. In C_Server, type in 
	"connect" and enter S_Server's ip (usually "localhost"), if needed. 
6. S_Server and C_Server will now communicate as outlined in steps 3-8.

7. If you would like to produce new Public/Private keys for Server CA, execute RSAKeyGen with the foldername
	of where you'd like to store the keys in the argument.
	