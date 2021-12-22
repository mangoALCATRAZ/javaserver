/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.StringTokenizer;

import javax.crypto.SecretKey;

import encryption_tools.RSA_Obj;

/**
 *
 * @author woah dude
 */
public class C_Server extends server {
    
	private String ts3_string;
	private String ts4_string;
	private String ts5_string;
	private String ts6_string;
	private String ts7_string;
	private String ts8_string;
	
	private String certificate_s;
	
	private SecretKey k_sess;
	
    public C_Server(){
        super();
        this.setThisPort(5002);
        System.out.println("Set port to 5002");
    }
    
    public void connectFunctionality() throws Exception{
    	this.addServerId("ID-Server", "ID_s");
    	
    	String folderPath = "C:\\Users\\Matt\\Documents\\NetBeansProjects\\Security_Lab_6\\ca_keys";
    	
    	this.retrieveAPublicKey("PK_ca", folderPath);
    	
    	this.step_3_C_to_S();
    	boolean verified_cert = this.step_4_S_to_C();
    	
    	if(verified_cert == true) {
    		String ktmp2Name = this.step_5_C_to_S();
    		this.step_6_S_to_C(ktmp2Name);
    		String kSessName = this.step_7_S_to_C();
    		this.step_8_S_to_C(kSessName);
    		
    	}
    	
    	
    	
    	
    }
    
    public void step_3_C_to_S() throws Exception {
    	long ts3 = this.timestampGen();
    	this.ts3_string = Long.toString(ts3);
    	System.out.println("\n\nStep 3: C -> S");
    	
    	String response = this.getIdByName("ID_s") + ";" + this.ts3_string;
    	System.out.println("\nResponse to be sent to S: " + response);
    	
    	this.getSender().sendAThingNoEncrypt(response);
    }
    
    public boolean step_4_S_to_C() throws Exception {
    	boolean retBool = false;
    	this.waitForListener();
    	
    	System.out.println("\n\nStep 4: S -> C");
    	String incomingPt = this.getListener().shareGet();
    	System.out.println("\nIncoming Plaintext: " + incomingPt);
    	if(server.checkNoOfDelims(incomingPt, 2) == true) {
    		StringTokenizer C_to_S_1 = new StringTokenizer(incomingPt, ";");
    		for(int i = 0; C_to_S_1.hasMoreElements(); i++) {
    			switch(i) {
    				case 0:
    					//PUblic Key S
    					String rawPublicKey = C_to_S_1.nextToken();
    					this.storeEncodedPublicKey(rawPublicKey, "PK_s");
    					
    					PublicKey decodedPub = RSA_Obj.PUblicKeyDecoder(rawPublicKey);
    					System.out.println("Encoded PUblic Key S Received: " + rawPublicKey);
    					System.out.println("Decoded PUblic Key S Received: " + decodedPub.toString());
    					String pubKeyName = "PK_s";
    					this.storePublicKeyOnKeyRing(decodedPub, pubKeyName);
    					System.out.println("Stored Public Key S\nName: " + pubKeyName);
    					break;
    				case 1:
    					// Certificate S
    					this.certificate_s = C_to_S_1.nextToken();
    					System.out.println("Received Certificate s: " + this.certificate_s);
    					break;
    				case 2:
    					// Timestamp 4
    					this.ts4_string = C_to_S_1.nextToken();
    					System.out.println("Received Timestamp 4: " + this.ts4_string);
    					break;
    				default:
    					break;
    			}
    		}
    		String ret = "err";
    		String pt = this.getIdByName("ID_s") + ";" + "ID-CA" + ";" + this.getEncodedPublicKeyByName("PK_s");
    		System.out.println("\nPlaintext to check Certificate with: " + pt);
    		if(this.verify(pt, this.certificate_s, this.getPubKeyByName("PK_ca")) == true) {
    			ret = "yes";
    			System.out.println("\n\nCertificate S Successfully Authenticated!");
    			retBool = true;
    		}
    		else {
    			ret = "no";
    			System.out.println("\n\nCertificate S authentication failed!");
    			
    		}
    		
    		this.getSender().sendAThingNoEncrypt(ret);
    		
    		
    	}
    	return retBool;
    }
    
    public String step_5_C_to_S() throws Exception {
    	String responseProto = new String();
    	
    	String kSessName = this.DESsessionKeyGen();
    	SecretKey kSess = this.getDESkeyByName(kSessName);
    	
    	String encodedKSessKey = RSA_Obj.DESKeyEncoder(kSess);
    	
    	System.out.println("\n\nStep 5: C - > S");
    	System.out.println("\nGenerated DES Key ktmp2:");
    	System.out.println("Name: " + kSessName);
    	System.out.println("Key: " + kSess.toString());
    	System.out.println("Encoded DES Key: " + encodedKSessKey);
    	
    	System.out.println("ID_C: ID-Client");
    	System.out.println("IP_c: localhost" );
    	System.out.println("Port_C: " + this.getPort());
    	
    	long ts5 = this.timestampGen();
    	this.ts5_string = Long.toString(ts5);
    	
    	System.out.println("TimeStamp 5: " + this.ts5_string);
    	
    	responseProto = encodedKSessKey + ";" + "ID-Client" + ";" + "localhost" + ";" + this.getPort() + ";" + this.ts5_string;
    	String ct = this.encrypt(responseProto, this.getPubKeyByName("PK_s"));
    	
    	System.out.println("\nPlaintext to be sent: " + responseProto);
    	System.out.println("Ciphertext to be sent: " + ct);
    	
    	this.getSender().sendAThingNoEncrypt(ct);
    	return kSessName;
    	
    }
    
    public void step_6_S_to_C(String ktmp2Name) throws Exception {
    	this.waitForListener();
    	String incomingCt = this.getListener().shareGet();
    	String incomingPlaintext = this.decrypt_DES(ktmp2Name, incomingCt);
    	
    	System.out.println("\n\nStep 6: S -> C");
    	
    	System.out.println("\nIncoming Ciphertext: " + incomingCt);
    	System.out.println("Plaintext: " + incomingPlaintext);
    	
    	if(this.checkNoOfDelims(incomingPlaintext, 3) == true) {
    		StringTokenizer st = new StringTokenizer(incomingPlaintext, ";");
    		for(int i = 0; st.hasMoreTokens(); i++) {
    			switch(i) {
    				case 0:
    					//K_sess
    					String encoded_k_sess = st.nextToken();
    					System.out.println("\nEncoded k_sess: " + encoded_k_sess);
    					SecretKey in = RSA_Obj.DESKeyDecoder(encoded_k_sess);
    					this.k_sess = in;
    					System.out.println("Decoded k_sess: " + this.k_sess.toString());
    					break;
    				case 1:
    					String lifetime_sess = st.nextToken();
    					System.out.println("Lifetime_sess: " + lifetime_sess);
    					break;
    				case 2:
    					String ID_c = st.nextToken();
    					System.out.println("ID_C: " + ID_c);
    					break;
    				case 3:
    					this.ts6_string = st.nextToken();
    					System.out.println("Timestamp 6: " + this.ts6_string);
    					break;
    				default:
    					break;
    			}
    		}
    	}
    	
    }
    
    public String step_7_S_to_C() throws Exception {
    	String req = "memo";
    	long ts7 = this.timestampGen();
    	this.ts7_string = Long.toString(ts7);
    	
    	System.out.println("\n\nStep 7: S -> C");
    	System.out.println("\nRequest req: " + req);
    	System.out.println("Timestamp 7: " + this.ts7_string);
    	
    	String proto =  req + ";" + ts7_string;
    	
    	String kSessname = this.DESsessionKeyStore(this.k_sess);
    	String encrypted = this.encrypt_DES(kSessname, proto);
    	
    	System.out.println("\nPlaintext to be sent: " + proto);
    	System.out.println("Ciphertext: ");
    	
    	this.getSender().sendAThingNoEncrypt(encrypted);
    	return kSessname;
    	
    }
    
    public void step_8_S_to_C(String k_sess_name) throws Exception {
    	this.waitForListener();
    	
    	String incomingCt = this.getListener().shareGet();
    	
    	System.out.println("\n\nStep 8: S -> C");
    	System.out.println("\nIncoming Ciphertext: " + incomingCt);
    	
    	String plaintext = this.decrypt_DES(k_sess_name, incomingCt);
    	System.out.println("Decrypted plaintext: " + plaintext);
    	
    	String data = new String();
    	
    	if(this.checkNoOfDelims(plaintext, 1) == true) {
    		StringTokenizer st = new StringTokenizer(plaintext, ";");
    		for(int i = 0; st.hasMoreTokens(); i++) {
    			switch(i) {
    				case 0:
    					data = st.nextToken();
    					System.out.println("\nData Received: " + data);
    					break;
    				case 1:
    					this.ts8_string = st.nextToken();
    					System.out.println("Timestamp 8: " + this.ts8_string);
    					break;
    				default:
    					break;
    			}
    		}
    		
    		String ret = new String();
    		if(data.equals("take cis3319 class this afternoon")) {
    			ret = "yes";
    			
    			System.out.println("\n\nAlgorithm finished. Exiting...");
    		}
    		else {
    			ret = "no";
    		}
    		
    		this.getSender().sendAThingNoEncrypt(ret);
    		
    		
    	}
    }
    
    
}
