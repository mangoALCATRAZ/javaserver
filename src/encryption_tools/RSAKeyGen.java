/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package encryption_tools;


import java.security.*;
import javax.crypto.*;


/**
 *
 * @author woah dude
 */
public class RSAKeyGen {
    private static PrivateKey genPrivKey;
    private static PrivateKey retreivedPrivKey;
    
    private static PublicKey genPubKey;
    private static PublicKey retreivedPubKey;
    
    
    
    public static void main(String[] args){
        String inPath = args[0];
        
        //initialize all to null
        genPrivKey = null;
        retreivedPrivKey = null;
        genPubKey = null;
        retreivedPubKey = null;
        
        
        try{
            genAndStoreKeys(inPath);
            retrieve(inPath);
            compare();
        }
        catch(Exception e){
            System.out.println("Err: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public static void compare(){
        if(genPrivKey == null || retreivedPrivKey == null || genPubKey == null || retreivedPubKey == null){
            System.out.println("Err: keys not initialized");
        }
        
        else{
            if(genPrivKey.equals(retreivedPrivKey) && genPubKey.equals(retreivedPubKey)){
                System.out.println("\nGenerated and Retrieved data is the same - KeyGen Success!");
            }
            else{
                System.out.println("\nGenerated and REtrieved data is not the same - KeyGen Failed!");
            }
        }
    }
    
    
    
    public static void retrieve(String in) throws Exception{
            RSA_Obj readObj = new RSA_Obj();
            PrivateKey priv = readObj.retrievePrivAddrAndKey(in);
            PublicKey pub = readObj.retrievePubAddrAndKey(in);
            System.out.println("\nRetrieved Public: " + pub.toString());
            System.out.println("Retrieved Private: " + priv.toString());
            
            retreivedPubKey = pub;
            retreivedPrivKey = priv;
            
    }
    
   
    
    public static void genAndStoreKeys(String in) throws Exception{
            KeyPair thisKp = RSAKeyGen.generateKeyPair();
            
            genPubKey = thisKp.getPublic();
            genPrivKey = thisKp.getPrivate();
        
            System.out.println("\n\nGenerated Public: " + thisKp.getPublic().toString());
            System.out.println("Generated Private: " + thisKp.getPrivate().toString());
            RSA_Obj writeObj = new RSA_Obj(thisKp);
            
            
            
            writeObj.storePrivateKey(in);
            writeObj.storePublicKey(in);
            
            
    }
    
    public static KeyPair generateKeyPair() throws Exception{
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        
        return pair;
    }
}
