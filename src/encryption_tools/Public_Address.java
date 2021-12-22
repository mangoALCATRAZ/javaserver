/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package encryption_tools;

import java.security.*;
import java.io.Serializable;

/**
 *
 * @author woah dude
 */
public class Public_Address implements Serializable{

    private final PublicKey pub;
    
    public Public_Address(PublicKey pubIn){
        this.pub = pubIn;
    }
    
    public PublicKey getPub(){
        return this.pub;
    }
    
}
