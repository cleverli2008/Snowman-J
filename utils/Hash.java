package utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** 
* Hash.java
* @author Li Cong
* @time   Dec 5, 2017 1:01:26 AM
* @version v1.0
*/
public class Hash {
	
	private MessageDigest hash_instance = null;
	
	public Hash(String hashName){
		
		try {
			this.hash_instance = MessageDigest.getInstance(hashName);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public byte[] hash(byte[] content){
		
		hash_instance.update(content);  
		return hash_instance.digest();
	
	}

}
