/*
 * Log:

4/25/2020 3:48PM:

Removed key entry from 
 */
package server;

import encryption_tools.DESEncryptDecrypt;
import encryption_tools.DESKeyGenerator;
import java.net.*;
import java.io.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
/**
 *
 * @author woah dude
 */
public class listenerThread extends Thread{
    private Socket sock;
    private volatile String shareWithOtherThread;
    private volatile boolean endFlag;
    
    private volatile boolean messageReceived;
    
    private volatile boolean decryptFlag;
    
    private String privateKey = "";
    
    private boolean passwordCheck;
    //private HMAC hmac;
    
    public listenerThread(Socket inSock){
        this.sock = inSock;
        this.endFlag = false;
        this.shareWithOtherThread = null; // null is default value
        //this.privateKey = keyIn;
        
        this.passwordCheck = false;
        
        this.messageReceived = false; // false by default.
        
        this.decryptFlag = false; // CHANGED false by default
        //hmac = in;
    }
    public boolean getMessageReceivedFlag() {
    	synchronized(this) {
    		return this.messageReceived;
    	}
    }
    
    public synchronized void toggleMessageReceivedFlag() {
    	if(this.messageReceived == false) {
    		this.messageReceived = true;
    		System.out.println("\nMessageReceived set to true.");
    	}
    	else {
    		this.messageReceived = false;
    		System.out.println("\nMessageReceived set to false");
    	}
    }
    
    public void shareSet(String in){
        this.shareWithOtherThread = in;
    }
    
    public void shareClear(){
        this.shareWithOtherThread = null;
    }
    
    public String shareGet(){
        return this.shareWithOtherThread;
    }
    
    public boolean getDecryptFlag(){
        return decryptFlag;
    }
    public void setDecryptFlag(boolean in){
        decryptFlag = in;
    }
    
    @Override
    public void run() {
        BufferedReader in;
        try{
            in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            
            System.out.println("\nListener Thread Ready.");
            
            while(!endFlag){
                String received = null;
                
                
                while(in.ready() == false){
                     //incoming ciphertext
                     TimeUnit.SECONDS.sleep(1);
                }
                if(this.getMessageReceivedFlag() == false) {
                	String get = in.readLine();
                
                	
                
                	if(get != null && !(get.equals(""))){
                		this.toggleMessageReceivedFlag();
                		received = get;
                
                    //if(this.decryptFlag == false){
                        //System.out.println("received plaintext: " + received);
                        	this.shareSet(received);
                    //}
                	}
                //else{
               
                    //ystem.out.println("received cyphertext: " + received);
                
                    // DECRYPTION GOES HERE, PRINT OUT RESULTING PLAINTEXT INSTEAD OF received
                
                
                    // we might need to allow input of a normal key below
                
                
                
                /*
                    This is the disabled DES decryption that occurs on the recieved message
                    This entire else statement should be reworked later because it is never exected.
                    
                    DESKeyGenerator kg = new DESKeyGenerator(privateKey);
                    String[] ReversedRoundKeyArray = kg.keyGenerator(kg.getKey());
                    ReversedRoundKeyArray = DESKeyGenerator.roundKeyArrayReversal(ReversedRoundKeyArray);
                    String pt = DESEncryptDecrypt.Decrypt(received, ReversedRoundKeyArray);
                */
                   
                    
                    
                    //String[] ReversedRoundKeyArray = DESKeyGenerator.keyGenerator(DESKeyGenerator.getKey());
                
                    
                    
                    
                    //System.out.println("\nThis key:" + kg.toString());
                // String rawMessage = ChatHelper.binaryStringToText(pt);
                
                
                    /*
                    String hmacChecksum = pt.substring(0, 256);
                    String bitMessage = pt.substring(256, pt.length());
                
                    System.out.println("\n\nCiphertext received: " + received);
                    System.out.println("    Length: " + received.length());
                
                    System.out.println("HMAC and plaintext append received: " + pt);
                    System.out.println("    Length: " + pt.length());
                
                    System.out.println("Plain message received: " + bitMessage);
                    System.out.println("    Length: " + bitMessage.length());
                
                    System.out.println("HMAC checksum received: " + hmacChecksum);
                    System.out.println("    Length: " + hmacChecksum.length());
                
                    String newChecksum = hmac.run(bitMessage);
                
                    System.out.println("New derived HMAC: " + newChecksum);
                    System.out.println("    Length: " + newChecksum.length());
                    if(newChecksum.equals(hmacChecksum)){
                    System.out.println("\n" + sock.getInetAddress().toString() + " says: " + ChatHelper.binaryStringToText(bitMessage));
                }
                else{
                    System.out.println("\n\nerror with hmac");
                }*/
                
                    //this.shareSet(pt);
                //}
                
                }  
                
            }
            
            sock.close();
            System.out.println("Server-aspect done running.");

            in.close();
        }
        catch(IOException e){
            
            System.out.print("\nListener thread: " + e);
            
            
        } catch (InterruptedException ex) {
            Logger.getLogger(listenerThread.class.getName()).log(Level.SEVERE, null, ex);
        }
   }
    
    // called by other thread
    public void end(){
        endFlag = true;
    }
}
    

