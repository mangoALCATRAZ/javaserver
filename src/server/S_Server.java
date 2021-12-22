/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.StringTokenizer;

import javax.crypto.SecretKey;

import encryption_tools.RSA_Obj;

/**
 *
 * @author woah dude
 */
public class S_Server extends server{
    private String K_tmp_name;
    
    private SecretKey K_sess;
    
    private String certificate_s;
    
    private String ts2_string;
    private String ts3_string;
    private String ts4_string;
    private String ts5_string;
    private String ts6_string;
    private String ts7_string;
	private String ts8_string;
    
    public S_Server(){
        super();
        System.out.println("|||||||||||||||| - - S_Server - - ||||||||||||||||");
    }
    
    @Override
    public void connectFunctionality() throws Exception{
         
        //System.out.println("\nPlease enter folderpath for CA's public key\n>");
        //String folderPath = super.scan.nextLine();
        
        String folderPath = "ca_keys";
        
        this.retrieveAPublicKey("PK_ca", folderPath);
        
        // PK_ca retrieved and stored
        
        this.addServerId("ID-Server", "ID_s");
        
        // this id_s stored
        
        this.step_1_S_to_CA();
        this.step_2_CA_to_S();
        
        // switches connection to C
        this.switchConnection();
        
        this.step_3_C_to_S();
        
        boolean certVerified = this.step_4_S_to_C();
        
        if(certVerified == true) {
        	String ktmp2Name = this.step_5_C_to_S();
        	String ksessName = this.step_6_S_to_C(ktmp2Name);
        	this.step_7_C_to_S(ksessName);
        	this.lastMethod();
        }
        
    }
    
    public void step_1_S_to_CA() throws Exception{
        // generate session key
        this.K_tmp_name = this.DESsessionKeyGen();
        SecretKey K_tmp1 = this.getDESkeyByName(this.K_tmp_name);
        System.out.println("\n\nGenerated DES key: " + K_tmp1.toString());
        
        
        long ts = this.timestampGen();
        String ts_string = Long.toString(ts);
        
        String ktmp1Encoded = RSA_Obj.DESKeyEncoder(K_tmp1);
        System.out.println("Encoded DES Key: " + ktmp1Encoded);
        
        String sendProto = ktmp1Encoded + ";" + this.getIdByName("ID_s") + ";" + ts_string;
        String ct = this.encrypt(sendProto, this.getPubKeyByName("PK_ca"));
        
        
        
        
        System.out.println("\nStep 1: S -> CA\nPlaintext:\n" + sendProto + "\nCiphertext:\n" + ct);
        
        this.getSender().sendAThingNoEncrypt(ct);
    }
    
    public void step_2_CA_to_S() throws Exception{
    	this.waitForListener();
    	
    	String incomingCt = this.getListener().shareGet();
    	String plainText = this.decrypt_DES(this.K_tmp_name, incomingCt);
    	
    	System.out.println("\n\nStep 2: CA -> S\nCiphertext Received:\n" + incomingCt + "\nPlaintext: " + plainText);
    	
    	if(server.checkNoOfDelims(plainText, 4) == true){
    		StringTokenizer CA_to_S = new StringTokenizer(plainText, ";");
    		for(int i = 0; CA_to_S.hasMoreElements(); i++) {
    			switch(i) {
    				case 0:
    					// public Key for S
    					String encodedPublicKey = CA_to_S.nextToken();
    					this.storeEncodedPublicKey(encodedPublicKey, "PK_s");
    					
    					PublicKey decodedPub = RSA_Obj.PUblicKeyDecoder(this.getEncodedPublicKeyByName("PK_s"));
    					System.out.println("Encoded Public Key S Received: " + this.getEncodedPublicKeyByName("PK_s"));
    					System.out.println("Decoded Public Key S Received: " + decodedPub.toString());
    					String pubKeyName = "PK_s";
    					this.storePublicKeyOnKeyRing(decodedPub, pubKeyName);
    					System.out.println("Stored Public Key S\nNAme: " + pubKeyName);
    					break;
    				case 1:
    					// private Key for S
    					String rawPrivateKey = CA_to_S.nextToken();
    					PrivateKey decodedPriv = RSA_Obj.PrivateKeyDecoder(rawPrivateKey);
    					System.out.println("Encoded Private Key S Received: " + rawPrivateKey);
    					System.out.println("Decoded PRivate Key S Received: " + decodedPriv.toString());
    					
    					KeyPair thisKp = new KeyPair(this.getPubKeyByName("PK_s"), decodedPriv);
    					String kpName = "s";
    					this.storeKeyPair(thisKp, "s");
    					
    					System.out.println("Private and Public Key for S stored in KeyPair of name: " + kpName); 
    					break;
    				case 2:
    					//Certificate S
    					String certificateS = CA_to_S.nextToken();
    					this.certificate_s = certificateS;
    					System.out.println("Received Signed Certificate S: " + this.certificate_s);
    					break;
    				case 3:
    					//ID_s
    					String ID_s = CA_to_S.nextToken();
    					System.out.println("Received ID_s: " + ID_s);
    					break;
    				case 4:
    					//TS_2
    					this.ts2_string = CA_to_S.nextToken();
    					System.out.println("Received Timestamp 2: " + ts2_string);
    					break;
    				default:
    					break;
    				
    			}
    		}
    		
    		//prepare to disconnect from 
    	}
    	
    	
    }
    public void switchConnection() {
		this.disconnect();
		// end current session with CA
		
		boolean whileFlag = false;
		while(whileFlag == false) {
			System.out.println("\n\nWill now attempt to connect to C\nHost or Join? >");
			String prompt = this.scan.nextLine();
			
			switch(prompt.toLowerCase()) {
				case "join":
					this.setHostFalse();
					whileFlag = true;
					break;
				case "host":
					this.setHostTrue();
					whileFlag = true;
					break;
				default:
					break;
			}
			
			
		}
		this.setThisPort(5002);
		System.out.println("Set port to  5002");
		
		System.out.println("\nIn the following prompt, please enter C Server's ip");
		this.connect();
	}
    
    public void step_3_C_to_S() throws Exception {
    	this.waitForListener();
    	
    	System.out.println("\n\nStep 3: C -> S");
    	String incomingPt = this.getListener().shareGet();
    	System.out.println("\nIncoming Plaintext: " + incomingPt);
    	if(server.checkNoOfDelims(incomingPt, 1) == true){
    		StringTokenizer C_to_S_1 = new StringTokenizer(incomingPt, ";");
    		for(int i = 0; C_to_S_1.hasMoreElements(); i++) {
    			switch(i) {
    				case 0:
    					String id_s = C_to_S_1.nextToken();
    					this.addServerId(id_s, "ID_s");
    					System.out.println("\nReceived ID_S: " + this.getIdByName("ID_s"));
    					break;
    				case 1:
    					this.ts3_string = C_to_S_1.nextToken();
    					System.out.println("Received Timestamp 3: " + this.ts3_string);
    			}
    		}
    		
    		
    	}
    }
    
    public boolean step_4_S_to_C() throws Exception {
    	boolean ret = false;
    	
    	String pubKeySEncoded = this.getEncodedPublicKeyByName("PK_s");
    	System.out.println("\n\nStep 4: S -> C\n\nPublic Key S: " + this.getPubKeyByName("PK_s"));
    	System.out.println("Encoded Public Key S: " + pubKeySEncoded);
    	
    	System.out.println("Certificate S: " + this.certificate_s);
    	
    	long ts4 = this.timestampGen();
    	this.ts4_string = Long.toString(ts4);
    	System.out.println("Timestamp 4: " + this.ts4_string + "\n");
    	
    	String toSend = pubKeySEncoded + ";" + this.certificate_s + ";" + this.ts4_string;
    	System.out.println("Plaintext to send: " + toSend);
    	
    	this.getSender().sendAThingNoEncrypt(toSend);
    	
    	this.waitForListener();
    	String response = this.getListener().shareGet();
    	
    	if(response.equals("err")) {
    		System.out.println("\n\nThere was an error..");
    	}
    	else if(response.equals("yes")) {
    		System.out.println("\n\nCertificate Authenticated!");
    		ret = true;
    	}
    	else if(response.equals("no")) {
    		System.out.println("\n\nAuthentication failed!");
    	}
    	
    	return ret;
    	
    }
    
    public String step_5_C_to_S() throws Exception{
    	this.waitForListener();
    	
    	String incomingCt = this.getListener().shareGet();
    	
    	System.out.println("\n\nStep 5: C -> S");
    	
    	String incomingPlaintext = this.decrypt(incomingCt, this.getKeyPairByName("s").getPrivate());
    	
    	System.out.println("\nIncoming Ciphertext: " + incomingCt);
    	System.out.println("Decrypted Plaintext: " + incomingPlaintext);
    	
    	String ktmp2Name = new String();
    	
    	
    	
    	if(this.checkNoOfDelims(incomingPlaintext, 4) == true) {
    		StringTokenizer C_to_S = new StringTokenizer(incomingPlaintext, ";");
    		for(int i = 0; C_to_S.hasMoreTokens(); i++) {
    			switch(i) {
    				case 0:
    					//DES ktmp2
    					String encodedKtmp2 = C_to_S.nextToken();
    					SecretKey decoded = RSA_Obj.DESKeyDecoder(encodedKtmp2);
    					ktmp2Name = this.DESsessionKeyStore(decoded);
    					
    					System.out.println("\nReceived encoded DES key: " + encodedKtmp2);
    					System.out.println("Decoded DES Key: " + decoded.toString());
    					break;
    				case 1:
    					//ID_c
    					String ID_c_string = C_to_S.nextToken();
    					this.addServerId(ID_c_string, "ID_c");
    					System.out.println("I_C: " + this.getServerIdByName("ID_c"));
    					break;
    				case 2:
    					// IP_c
    					String Ip_c = C_to_S.nextToken();
    					System.out.println("IP_c: " + Ip_c);
    					break;
    				case 3:
    					// Port_c
    					String Port_c = C_to_S.nextToken();
    					System.out.println("Port_c: " + Port_c);
    					break;
    				case 4:
    					//Timestamp 5
    					this.ts5_string = C_to_S.nextToken();
    					System.out.println("Timestamp 5: " + this.ts5_string);
    					break;
    				default:
    					break;
    			}
    		}
    		
    		
    	}
    	
    	return ktmp2Name;
    }
    
    public String step_6_S_to_C(String ktmp2Name) throws Exception {
    	SecretKey ktmp2 = this.getDESkeyByName(ktmp2Name);
    	
    	//generate DES key K_sess
    	String k_sess_name = this.DESsessionKeyGen();
    	SecretKey k_sess = this.getDESkeyByName(k_sess_name);
    	this.K_sess = k_sess;
    	
    	String k_sess_encoded = RSA_Obj.DESKeyEncoder(k_sess);
    	System.out.println("\n\nStep 6: S -> C");
    	System.out.println("\nGenerated DES key K_sess:" + k_sess.toString());
    	System.out.println("Encoded k_sess: " + k_sess_encoded);
    	
    	
    	int lifetime_sess = 86400;
    	String lifetime_sess_String = Integer.toString(lifetime_sess);
    	System.out.println("Lifetime_sess: " + lifetime_sess_String);
    	
    	String ID_c = "ID-Client";
    	System.out.println("ID_C: " + ID_c);
    	
    	long ts6 = this.timestampGen();
    	this.ts6_string = Long.toString(ts6);
    	
    	System.out.println("Timestamp 6: " + this.ts6_string);
    	String plaintext = k_sess_encoded + ";" + lifetime_sess_String + ";" + ID_c + ";" + this.ts6_string;
    	String ciphertext = this.encrypt_DES(ktmp2Name, plaintext);
    	
    	System.out.println("\nPlaintext to be sent: " + plaintext);
    	System.out.println("Ciphertext: " + ciphertext);
    	
    	this.getSender().sendAThingNoEncrypt(ciphertext);
    	
    	return k_sess_name;
    	
    	
    	
    }
    public void step_7_C_to_S(String k_sess_name) throws Exception {
    	this.waitForListener();
    	
    	String incomingCt = this.getListener().shareGet();
    	System.out.println("\n\nStep 7: C -> S");
    	
    	String plaintext = this.decrypt_DES(k_sess_name, incomingCt);
    	
    	System.out.println("\nIncoming ciphertext: " + incomingCt);
    	System.out.println("Decrypted plaintext: " + plaintext);
    	
    	String req = new String();
    	
    	if(this.checkNoOfDelims(plaintext, 1) == true) {
    		StringTokenizer st = new StringTokenizer(plaintext, ";");
    		for(int i = 0; st.hasMoreTokens(); i++) {
    			switch(i) {
    				case 0:
    					//req
    					req = st.nextToken();
    					System.out.println("\nRequest req: " + req);
    					break;
    				case 1:
    					//timestamp 7
    					this.ts7_string = st.nextToken();
    					System.out.println("Timestamp 7: " + this.ts7_string);
    					break;
    				default:
    					break;
    					
    			}
    		}
    		
    		if(req.equals("memo")) {
    			String data = "take cis3319 class this afternoon";
    			
    			long ts8 = this.timestampGen();
    			this.ts8_string = Long.toString(ts8);
    			
    			System.out.println("\nData to be sent: " + data);
    			System.out.println("Timestamp 8: " + this.ts8_string);
    			
    			String proto = data + ";" + this.ts8_string;
    			System.out.println("\nPlaintext to be sent: " + proto);
    			
    			String ct = this.encrypt_DES(k_sess_name, proto);
    			System.out.println("Ciphertext: " + ct);
    			
    			this.getSender().sendAThingNoEncrypt(ct);
    		}
    	}
    }
    
    public void lastMethod() throws Exception{
    	this.waitForListener();
    	
    	String response = this.getListener().shareGet();
    	
    	if(response.equals("yes")) {
    		System.out.println("\n\nEverything ran successffully, exiting...");
    	}
    	else {
    		System.out.println("\n\nThere was an issue...");
    	}
    }
    
    
}
