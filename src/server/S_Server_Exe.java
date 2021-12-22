/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package server;


/**
 *
 * @author woah dude
 */
public class S_Server_Exe {
    private static S_Server serv;
    
    public static void main(String[] args){
        serv = new S_Server();
        
        serv.terminalStart();
        
        //end
    }
}
