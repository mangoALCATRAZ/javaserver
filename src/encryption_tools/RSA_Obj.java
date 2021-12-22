/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package encryption_tools;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Serializable;

import java.io.ObjectOutputStream;
import java.io.FileOutputStream;

import java.io.FileInputStream;
import java.io.ObjectInputStream;

import java.io.IOException;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
/**
 *
 * wrapper for KeyPair generator that creates serializable objects out of
 * its public and private keys.
 * @author woah dude
 */
public class RSA_Obj{
    private KeyPair RSAkp;
    private PublicKey pub;
    private PrivateKey priv;
    
    private Private_Address addrPriv;
    private Public_Address addrPub;
    
    public RSA_Obj(KeyPair in){
    
        this.RSAkp = in;
        this.pub = this.RSAkp.getPublic();
        this.priv = this.RSAkp.getPrivate();
        
        this.addrPriv = new Private_Address(this.priv);
        this.addrPub = new Public_Address(this.pub);
    }
    
    public RSA_Obj(){
        this.RSAkp = null;
        this.pub = null;
        this.priv = null;
        
    }
    
    public PrivateKey retrievePrivAddrAndKey(String folderPath) throws Exception{
        FileInputStream fin = null;
        ObjectInputStream ois = null;
        
        String completePath = folderPath + "\\private.ser";
                
        fin = new FileInputStream(completePath);
        ois = new ObjectInputStream(fin);
        
        this.addrPriv = (Private_Address) ois.readObject();
        this.priv = this.addrPriv.getPriv();
        
        return this.priv;
        
    }
    
    public PublicKey retrievePubAddrAndKey(String folderPath) throws Exception{
        FileInputStream fin = null;
        ObjectInputStream ois = null;
        
        String completePath = folderPath + "\\public.ser";
        
        fin = new FileInputStream(completePath);
        ois = new ObjectInputStream(fin);
        
        this.addrPub = (Public_Address) ois.readObject();
        this.pub = this.addrPub.getPub();
        
        return this.pub;
    }
    
    public void storePrivateKey(String inFolderPath) throws Exception{
        String filename = "\\private.ser";
        String completePath = inFolderPath + filename;
        
        FileOutputStream fout = null;
        ObjectOutputStream oos = null;
        
        fout = new FileOutputStream(completePath);
        oos = new ObjectOutputStream(fout);
        oos.writeObject(this.addrPriv);
        
        System.out.println("\nDone storing private key to " + completePath);
        
        if(fout != null){
            fout.close();
        }
        if(oos != null){
            oos.close();
        }
        
    }
    
    public void storePublicKey(String inFolderPath) throws Exception{
        String filename = "\\public.ser";
        String completePath = inFolderPath + filename;
        
        FileOutputStream fout = null;
        ObjectOutputStream oos = null;
        
        fout = new FileOutputStream(completePath);
        oos = new ObjectOutputStream(fout);
        oos.writeObject(this.addrPub);
        
        System.out.println("\nDone storing public key to " + completePath);
        
        fout.close();
        oos.close();
    }
    
    public KeyPair getKeyPair(){
        return this.RSAkp;
    }
    
    public PublicKey getPub(){
        return this.pub;
    }
    
    public PrivateKey getPriv(){
        return this.priv;
    }
    
    public void setKeyPair(KeyPair in){
        this.RSAkp = in;
    }
    
    public static String DESKeyEncoder(SecretKey in) {
    	return Base64.getEncoder().encodeToString(in.getEncoded());
    	
    }
    
    public static SecretKey DESKeyDecoder(String in) {
    	byte[] decodedKey = Base64.getDecoder().decode(in);
    	
    	SecretKey ret = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
    	return ret;
    }
    
    public static String PublicKeyEncoder(PublicKey in) throws NoSuchAlgorithmException, InvalidKeySpecException {
    	KeyFactory fact = KeyFactory.getInstance("RSA");
    	X509EncodedKeySpec spec = fact.getKeySpec(in, X509EncodedKeySpec.class);
    	return Base64.getEncoder().encodeToString(spec.getEncoded());
    }
    
    public static PublicKey PUblicKeyDecoder(String in) throws Exception {
    	byte[] byteKey = Base64.getDecoder().decode(in.getBytes());
    	X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
    	KeyFactory kf = KeyFactory.getInstance("RSA");
    	
    	return kf.generatePublic(X509publicKey);
    }
    public static String PrivateKeyEncoder(PrivateKey in) throws NoSuchAlgorithmException, InvalidKeySpecException {
    	KeyFactory fact = KeyFactory.getInstance("RSA");
    	PKCS8EncodedKeySpec spec = fact.getKeySpec(in, PKCS8EncodedKeySpec.class);
    	byte[] packed = spec.getEncoded();
    	String key64 = Base64.getEncoder().encodeToString(packed);
    	Arrays.fill(packed, (byte) 0);
    	return key64;
    }
    public static PrivateKey PrivateKeyDecoder(String in) throws NoSuchAlgorithmException, InvalidKeySpecException {
    	byte[] clear = Base64.getDecoder().decode(in.getBytes());
    	PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
    	KeyFactory fact = KeyFactory.getInstance("RSA");
    	PrivateKey priv = fact.generatePrivate(keySpec);
    	Arrays.fill(clear, (byte) 0);
    	return priv;
    }
    
    /*
    public static String serializeDESkey(SecretKey in) throws Exception{
    	ByteArrayOutputStream bo = new ByteArrayOutputStream();
    	ObjectOutputStream so = new ObjectOutputStream(bo);
    	so.writeObject(in);
    	so.flush();
    	String ret = bo.toString();
    	
    	return ret;
    }
    
    public static SecretKey deserializeDESkey(String in) throws Exception{
    	byte b[] = in.getBytes();
    	ByteArrayInputStream bi = new ByteArrayInputStream(b);
    	ObjectInputStream si = new ObjectInputStream(bi);
    	SecretKey ret = (SecretKey) si.readObject();
    	
    	return ret;
    }
    */
    
    
    public static String serializePublicKey(PublicKey in) throws Exception{
    	ByteArrayOutputStream bo = new ByteArrayOutputStream();
    	ObjectOutputStream so = new ObjectOutputStream(bo);
    	so.writeObject(in);
    	so.flush();
    	String ret = bo.toString();
    	
    	return ret;
    }
    
    public static PublicKey deseralizePublicKey(String in) throws Exception{
    	byte b[] = in.getBytes();
    	ByteArrayInputStream bi = new ByteArrayInputStream(b);
    	ObjectInputStream si = new ObjectInputStream(bi);
    	PublicKey ret = (PublicKey) si.readObject();
    	
    	return ret;
    }
    
    public static String serializePrivateKey(PrivateKey in) throws Exception{
    	ByteArrayOutputStream bo = new ByteArrayOutputStream();
    	ObjectOutputStream so = new ObjectOutputStream(bo);
    	so.writeObject(in);
    	so.flush();
    	String ret = bo.toString();
    	
    	return ret;
    }
    
    public static PrivateKey desereializePrivateKey(String in) throws Exception{
    	byte b[] = in.getBytes();
    	ByteArrayInputStream bi = new ByteArrayInputStream(b);
    	ObjectInputStream si = new ObjectInputStream(bi);
    	PrivateKey ret = (PrivateKey) si.readObject();
    	
    	return ret;
    }
    
    
    public static String serializeKeyPair(KeyPair in) throws Exception{
        
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        ObjectOutputStream so = new ObjectOutputStream(bo);
        so.writeObject(in);
        so.flush();
        String ret = bo.toString();
        
        return ret;
        
    }
    
    public static KeyPair deserializeKeyPair(String in) throws Exception{
        byte b[] = in.getBytes();
        ByteArrayInputStream bi = new ByteArrayInputStream(b);
        ObjectInputStream si = new ObjectInputStream(bi);
        KeyPair ret = (KeyPair) si.readObject();
        
        return ret;
    }
    
    
}
