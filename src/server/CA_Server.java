/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.StringTokenizer;

import javax.crypto.SecretKey;

import encryption_tools.RSAKeyGen;
import encryption_tools.RSA_Obj;

/**
 *
 * @author woah dude
 */
public class CA_Server extends server{
    
	private String ts1_string;
	
	
    public CA_Server(){
        super();
        System.out.println("\n\n|||||||||||||||| - - CA_Server - - ||||||||||||||||");
    } 
    
    @Override
    public void connectFunctionality() throws Exception{
        //System.out.println("\nPlease enter the folderpath for CA's Keys:");
        //String folderPath = super.scan.nextLine();
        
        //change this vvvvvvvvvvvv
        String folderPath = "ca_keys";
        System.out.println("path: " + new File("..").getCanonicalPath());
        
        this.retreiveMyKeyset(folderPath);
        // key should be stored under name "mine" now
        
        this.addServerId("ID_ca", "ID_CA");
        this.setMyId(this.getServerIdByName("ID_ca"));
        // add own server id
        
        try {
			if(this.step_2_CA_to_S() == false) {
				
			}
			else {
				System.out.println("\nErr with input from server.");
			}
		} catch (Throwable e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    public boolean step_2_CA_to_S() throws Exception, Throwable{
        boolean err = false;
    	
        this.waitForListener();
        
        String incomingCt = this.getListener().shareGet();
        System.out.println("\n\nStep 1: S -> CA\n\nIncoming ciphertext:");
        System.out.print(incomingCt);
        
        PrivateKey myPrivate = this.getMyKey().getPrivate();
        String plaintext = this.decrypt(incomingCt, myPrivate);
        
        System.out.println("\nDecrypted Plaintext:\n" + plaintext);
        
        String DEStempKeyName = new String();
        
        if(server.checkNoOfDelims(plaintext, 2) == true) {
        	StringTokenizer S_to_CA = new StringTokenizer(plaintext, ";");
        	for(int i = 0; S_to_CA.hasMoreElements(); i++) {
        		switch(i) {
        			case 0:
        				String newSessKey = S_to_CA.nextToken();
        				SecretKey decodedDESTemp1 = RSA_Obj.DESKeyDecoder(newSessKey);
        				System.out.println("Encoded DES received: ");
        				DEStempKeyName =this.DESsessionKeyStore(decodedDESTemp1);
        				System.out.println("\nStored DES session key\nName: " + DEStempKeyName + "\nKey: " + this.getDESkeyByName(DEStempKeyName).toString());
        				break;
        			case 1:
        				String newID_s = S_to_CA.nextToken();
        				this.addServerId(newID_s, "ID_s");
        				System.out.println("Stored Received ID_s: " + newID_s);
        				break;
        			case 2:
        				this.ts1_string = S_to_CA.nextToken();
        				System.out.println("Stored Received Timestamp 1: " + this.ts1_string);
        				break;
        		}
        	}
        	
        	//prepare response below
        	System.out.println("\nStep 2: CA -> S");
        	
        	
        	
        	//first, develop S RSA keys
        	
        	KeyPair PK_s = RSAKeyGen.generateKeyPair();
        	this.storeKeyPair(PK_s, "pk_s");
        	
        	
        	
        	//KeyPair SK_s = RSAKeyGen.generateKeyPair();
        	//this.storeKeyPair(SK_s, "sk_s");
        	
        	
        	
        	//generate certificate Cert_s
        	
        	PublicKey public_key_s = this.getKeyPairByName("pk_s").getPublic();
        	PrivateKey private_key_s = this.getKeyPairByName("pk_s").getPrivate();
        	
        	System.out.println("\nPUblic Key for S: " + public_key_s.toString());
        	System.out.println("Private Key for S: " + private_key_s.toString());
        	
        	//String serializedPublic = RSA_Obj.serializePublicKey(public_key_s);
        	//String serializedPrivate = RSA_Obj.serializePrivateKey(private_key_s);
        	
        	//System.out.println("\nSerialized Public Key S: " + serializedPublic);
        	//System.out.println("Serialized Private Key S: " + serializedPrivate);
        	
        	String encodePub = RSA_Obj.PublicKeyEncoder(public_key_s);
        	
        	this.storeEncodedPublicKey(encodePub, "PK_s");
        	
        	String encodePriv = RSA_Obj.PrivateKeyEncoder(private_key_s);
        	System.out.println("\nEncoded String Public Key: " + this.getEncodedPublicKeyByName("PK_s"));
        	System.out.println("Encoded String Private Key: " + encodePriv);
        	
        	String certProto = this.getIdByName("ID_s") + ";" + "ID-CA" + ";" + this.getEncodedPublicKeyByName("PK_s");
        	
        	String signedCert_S = this.sign(certProto, this.getMyKey().getPrivate());
        	System.out.println("\nCertificate_S: " + certProto);
        	System.out.println("Signed Certificate_S with private key CA: " + signedCert_S);
        	
        	
        	
        	//generate response to S
        	
        	long ts_2 = this.timestampGen();
        	String ts2_String = Long.toString(ts_2);
        	
        	String responseProto = encodePub + ";" + encodePriv + ";" + signedCert_S + ";" + this.getServerIdByName("ID_S") + ";" + ts2_String;
        	System.out.println("Plaintext to be sent: " + responseProto);
        	
        	//Encrypt with DES sess key and send to 
        	
        	String encrypted = this.encrypt_DES(DEStempKeyName, responseProto);
        	System.out.print("Sent Ciphertext: " + encrypted);
        	
        	
        	
        	this.getSender().sendAThingNoEncrypt(encrypted);
        	
        }
        else {
        	err = true;
        }
        
        return err;
    }
    
    
}
