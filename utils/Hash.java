package utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @ClassName: Hash
 * @Description: Provide hash functions
 * @author:cleverli2008
 * @date:2021/11/26
 * @version: v1.0
 */

public class Hash {

	private MessageDigest hash_instance = null;

	public Hash(String hashName) {

		try {
			this.hash_instance = MessageDigest.getInstance(hashName);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public byte[] hash(byte[] content) {
		hash_instance.update(content);
		return hash_instance.digest();

	}

}
