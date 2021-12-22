/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import desencryptedchat.ChatHelper;


import java.net.*;
import java.util.*;

import encryption_tools.*;
import encryption_tools.KeyGenerator_DES;

import java.nio.charset.Charset;

import javax.crypto.*;
import java.security.*;

import java.sql.Timestamp;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author woah dude
 */
public abstract class server {
    private Socket currentSocket;
    private int port = 5001;
    
    private HashMap<String, SecretKey> DESkeyCollection; // String index, String key
    private HashMap<String, KeyPair> RSAkeyCollection; // String index, KeyPair keys
    
    
    private HashMap<String, String> serverIdCollection;
    
    private String myId;
    
    
    private HashMap<String, PublicKey> RSAPublicKeyRing;
    private HashMap<String, String> EncodedPublicKeyCollection;
    
    private listenerThread listen;
    private SenderClass sender;
    
    private boolean host = true; // true by default
    
    public Scanner scan;
    
    
    
    public server(){
        //initializes Socket to null.
        this.currentSocket = null;
        this.scan = new Scanner(System.in);
        
        this.DESkeyCollection = new HashMap<>();
        this.RSAkeyCollection = new HashMap<>();
        this.serverIdCollection = new HashMap<>();
        this.RSAPublicKeyRing = new HashMap<>();
        this.EncodedPublicKeyCollection = new HashMap<>();
        
        this.listen = null;
        this.sender = null;
        
        
        
    }
    
    public void initListener(){
        if(this.getCurrentSocket() != null){
            this.listen = new listenerThread(this.getCurrentSocket());
        }
        else{
            System.out.println("\nErr: Not connected to peer.");
        }
        
        
    }
    
    public void initSender(){
        if(this.getCurrentSocket() != null){
            try{    
                this.sender = new SenderClass(this.getCurrentSocket());
            }
            catch(Exception e){
                System.out.println("Err: " + e.getMessage());
                this.sender = null; // reset back to null
            }
        }
        else{
            System.out.println("\nErr: Not connected to peer.");
        }
        
    }
    
    
    public void listenerThreadStart(){
        if(this.getListener() != null){
            this.listen.start();
        }
        else{
            System.out.println("Err: Listener not initialized!");
        }
    }
    
    public listenerThread getListener(){ // returns null if not init
        return this.listen;
    }
    
    
    
    public SenderClass getSender(){
        return this.sender;
    }
    
    public Socket getCurrentSocket(){
        return this.currentSocket;
    }
    
    // call this first
    public void terminalStart(){
        boolean isRunning = true;
        while(isRunning == true){
            System.out.println("\nServer is running. Please enter command: \n\n");
            System.out.println("connect - Connect to another..");
            System.out.println("print - Print details of current connection.");
            System.out.println("host - Set this server to host TRUE BY DEFAULT");
            System.out.println("join - Set this server to join");
            System.out.println("quit - quit");
            System.out.println("set port - Set the port this server works on.");
        
            System.out.println("\nThis server is currently set to: ");
            if(host == true){
                System.out.println("host");
            }
            else{
                System.out.println("join");
            }
        
            System.out.print(">");
            String inTerm = this.scan.nextLine();
        
            switch(inTerm.toLowerCase()){
                case "connect":
                    this.connect(); // connects and executes functionality
                    try{
                        //executes each server's individual functionality
                        this.connectFunctionality();
                        
                        
                        
                    }
                    catch(Exception e){
                        System.out.println("Err: " + e.getMessage());
                        e.printStackTrace();
                    }
                     
                    this.disconnect(); // disconnects and cleans up
                    isRunning = false; // disables loop
                    break;
                case "host":
                    this.setHostTrue();
                    break;
                case "join":
                    this.setHostFalse();
                    break;
                case "set port":
                    this.setPort();
                    break;
                case "quit":
                    System.out.println("\nShutting down...");
                    isRunning = false;
                    break;
            }
        
        }
        
        System.out.println("\n\nServer shutting down...");
    }
    
    public void setThisPort(int portIn) {
    	this.port = portIn;
    }
    public void setPort(){
        System.out.println("\nPlease enter new port: ");
        String portIn = this.scan.nextLine();
        
        this.port = Integer.parseInt(portIn);
    }
    public int getPort(){
        return this.port;
    }
    
    public void connect(){
        if(host == true){
            try{
                this.setSocket(NetworkMethods.hostMethod(this.getPort()));
                
                // if all goes well, socket is connected now.
                
                
                
            }
            catch(Exception e){
                System.out.println("Err: " + e.getMessage());
                this.setSocket(null); // revert back to null
                return;
            }
        }
        else{ // join server
            System.out.println("\nPlease enter ip to connect:");
            try{
                this.setSocket(NetworkMethods.joinMethod(this.getPort(), this.scan));
            }
            catch(Exception e){
                System.out.println("Err: " + e.getMessage());
                this.setSocket(null);
                return;
            }
        }
        
        this.initListener();
        this.initSender();
                
        this.listenerThreadStart();
                
        System.out.println("\nSuccessfully finished connection sequence.");
                
        //this calls the inherited class' functionality method.
        
        
        
        
    }
    
    public abstract void connectFunctionality() throws Exception;
    
    public void addServerId(String in, String name){
        this.serverIdCollection.put(name, in);
    }
    
    public String getServerIdByName(String name) throws Exception{
        return this.serverIdCollection.get(name);
        
    }
    
    public String DESsessionKeyGen() throws NoSuchAlgorithmException{
        KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
        SecretKey myDESKey = keygenerator.generateKey(); 
        
    	
    	
    	//String rando = randomStringGenerator(15);
        //String key = ChatHelper.keyConverter(rando);
        
        int keyNum = this.DESkeyCollection.size() + 1;
        String name = "sess" + keyNum;
        this.DESkeyCollection.put(name, myDESKey);
        
        System.out.println("\nGenerated DES key\nName: " + name);
        
        return name;
    }
    
    public String DESsessionKeyStore(SecretKey inKey) {
    	int keyNum = this.DESkeyCollection.size() + 1;
    	String name  = "sess" + keyNum;
    	
    	SecretKey store = inKey;
    	this.DESkeyCollection.put(name, store);
    	//System.out.println("\nStored DES key\nName: " + name + "\nKey: " + inKey);
    	
    	return name;
    }
    
    public void storePublicKeyOnKeyRing(PublicKey in, String name) {
    	this.RSAPublicKeyRing.put(name, in);
    }
    
    public void storeEncodedPublicKey(String in, String name) {
    	this.EncodedPublicKeyCollection.put(name, in);
    	
    }
    public String getEncodedPublicKeyByName(String name) {
    	return this.EncodedPublicKeyCollection.get(name);
    }
    
    public void storeKeyPair(KeyPair in, String name) {
    	this.RSAkeyCollection.put(name, in);
    }
    
    public KeyPair getKeyPairByName(String name) {
    	return this.RSAkeyCollection.get(name);
    }
        
    public static String randomStringGenerator(int size){
        String ret;
        
        byte[] array = new byte[size];
        new Random().nextBytes(array);
        ret = new String(array, Charset.forName("UTF-8"));
        
        return ret;
    }
        
        
        
    
    
    public void setSocket(Socket in){
        this.currentSocket = in;
    }
    public void disconnect(){
        if(this.currentSocket == null){
            System.out.println("\n\nNot currently connected.");
            
        }
        else{
            try{
                this.currentSocket.close();
                this.currentSocket = null;
                this.sender.finalize();
                this.listen.end();
                
                System.out.println("\nConnection successfully closed.");
            }
            catch(Exception e){
                System.out.println("\nErr: " + e.getMessage());
            } catch (Throwable ex) {
                Logger.getLogger(server.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    public void setHostTrue(){
        if(this.currentSocket != null){
            System.out.println("Err: Cannot change host/join status while connected.");
        }
        else if(this.host == true){
            System.out.println("\nAlready set to host.");
        }
        else{
            this.host = true;
            System.out.println("\nSuccessfully set host to true.");
        }
        
    }
    
    public void setHostFalse(){
        if(this.currentSocket != null){
            System.out.println("Err: Cannot change host/join status whlie connected.");
        }
        else if(this.host == false){
            System.out.println("\nHost alredy set to false.");
        }
        else{
            this.host = false;
        }
    }
    
    
    
    public void retreiveMyKeyset(String folderPath) throws Exception{
        RSA_Obj readObj = new RSA_Obj();
        PrivateKey priv = readObj.retrievePrivAddrAndKey(folderPath);
        PublicKey pub = readObj.retrievePubAddrAndKey(folderPath);
        
        KeyPair thiskp = new KeyPair(pub, priv);
        this.RSAkeyCollection.put("mine", thiskp);
    }
    
    public void retrieveAPublicKey(String name, String folderPath) throws Exception{
        RSA_Obj readObj = new RSA_Obj();
        PublicKey pub = readObj.retrievePubAddrAndKey(folderPath);
        
        this.RSAPublicKeyRing.put(name, pub);
        System.out.println("\nRetrieved public key:\n " + pub.toString() + "\nStored in slot: " + name);
    }
    
    public KeyPair getMyKey() throws Exception{
        return RSAkeyCollection.get("mine");
    }
    
    public PublicKey getPubKeyByName(String in) throws Exception{
        return this.RSAPublicKeyRing.get(in);
    }
    
    public String getIdByName(String in) throws Exception{
        return this.serverIdCollection.get(in);
    }
    
    public SecretKey getDESkeyByName(String in) throws Exception{
        return this.DESkeyCollection.get(in);
    }
    
    
    public long timestampGen(){
        Timestamp ts = new Timestamp(System.currentTimeMillis());
        long ret = ts.getTime();
        
        
        return ret;
    }
    
    
    
    public static String encrypt(String plainText, PublicKey publicKey) throws Exception{
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes("UTF-8"));
        
        return Base64.getEncoder().encodeToString(cipherText);
    }
    
    public String encrypt_DES(String keyName, String plainText) throws Exception {
    	SecretKey thisKey = this.getDESkeyByName(keyName);
    	Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    	byte[] text = plainText.getBytes();
    	desCipher.init(Cipher.ENCRYPT_MODE, thisKey);
    	byte[] textEncrypted = desCipher.doFinal(text);
    	
    	return Base64.getEncoder().encodeToString((textEncrypted));
    }
    
    
    public String decrypt_DES(String keyName, String cipherText) throws Exception {
    	byte[] in = Base64.getDecoder().decode(cipherText);
    	SecretKey thisKey = this.getDESkeyByName(keyName);
    	
    	Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    	desCipher.init(Cipher.DECRYPT_MODE, thisKey);
    	byte[] textDecrypted = desCipher.doFinal(in);
    	
    	return new String(textDecrypted, "UTF-8");
    }
    
    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception{
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        return new String(decryptCipher.doFinal(bytes), "UTF-8");
        
    }
    
    public static String sign(String plainText, PrivateKey privateKey) throws Exception{
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes("UTF-8"));
        
        byte[] signature = privateSignature.sign();
        
        return Base64.getEncoder().encodeToString(signature);
    }
    
    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception{
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF-8"));
        
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        
        return publicSignature.verify(signatureBytes);
    }
    
    public void setMyId(String in){
        this.myId = in;
    }
    
    public String getMyId(){
        return this.myId;
    }
    
    public void waitForListener() throws Exception{
        System.out.println("\nWaiting for response..");
    	while(this.getListener().getMessageReceivedFlag() == false){
            TimeUnit.SECONDS.sleep(2);
        }

        
        // done waiting
        this.getListener().toggleMessageReceivedFlag(); // set back to false
        System.out.println("Response Received!\n");
    }
   
    public static boolean checkNoOfDelims(String inResponse, int num){
        boolean ret = false;
        
        int count = 0;
        
        for(int i = 0; i < inResponse.length(); i++){
            
            if(inResponse.charAt(i) == ';'){
                count++;
            }
        }
        if(count == num){
            ret = true;
        }
        
        return ret;
    }
    
    
    
}
