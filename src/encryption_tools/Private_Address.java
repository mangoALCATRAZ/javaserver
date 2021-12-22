/*
 * This is written to external files by RSA_Obj

*/
package encryption_tools;

import java.security.*;
import java.io.Serializable;
/**
 *
 * @author woah dude
 */
public class Private_Address implements Serializable {
    private final PrivateKey priv;
    
    public Private_Address(PrivateKey privIn){
        this.priv = privIn;
    }
    
    public PrivateKey getPriv(){
        return this.priv;
    }
}
