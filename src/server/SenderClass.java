/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import encryption_tools.DESEncryptDecrypt;
import encryption_tools.DESKeyGenerator;
import desencryptedchat.pWriter;
import java.io.IOException;
import java.net.*;
import java.io.*;
/**
 *
 * @author woah dude
 */
public class SenderClass {
    private Socket sock;
    private pWriter wrapper;
    private PrintWriter print;
    
    public SenderClass(Socket inSock) throws IOException{
        this.sock = inSock;
        this.wrapper = new pWriter();
        this.wrapper.set(sock);
        this.print = wrapper.get();
    }
    public void sendAThing(String keyIn, String input) throws Exception, Throwable{
        try{
            DESEncryptDecrypt ed = new DESEncryptDecrypt(input, true);
        
            DESKeyGenerator kg = new DESKeyGenerator(keyIn);
            String[] RoundKeyArray = kg.keyGenerator(keyIn);
            
            //System.out.println("\nThis key:" + kg.toString());
            
            String ciphertext = ed.Encrypt(ed.getInitialMessage(), RoundKeyArray);
            
        
            this.print.println(ciphertext);
            
            System.out.println("Sent ciphertext:" + ciphertext);
        }
        catch(Exception e){
            System.out.println(e.getMessage());
            
            
            this.finalize();
            
           
            
            throw e;
        }
    }
    public void sendAThingNoEncrypt(String input){
        this.print.println(input);
        this.print.flush();
    }
    
    public void finalize() throws Throwable {
        super.finalize();
        
        this.sock.close();
        this.print.close();
        
    }
}
