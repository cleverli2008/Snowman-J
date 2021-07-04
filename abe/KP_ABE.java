package abe;

/*
 * interface for all ABE instances
 * all concrete scheme must implement this interface.
 * author: licong
 */

public interface KP_ABE {
	
	/**
	 * @return Key array which contains public key and master key
	 */
	Key[] setup();
		
	/**
	 * @param publicKey the public key
	 * @param masterKey the master key
	 * @param attributes the attributes which used to generate secret key
	 * @return intermediate secret key
	 */
	SecretKey keygen(Key publicKey, Key masterKey, Policy policy, String ID, Key extensionItem);
	
	/**
	 * @param publicKey the public key 
	 * @param attributes the attributes which used to generate secret key
	 * @param message the plaintext to be encrypted 
	 * @return ciphertext object
	 */
	Ciphertext encrypt(Key publicKey, Attribute[] attributes , byte[] message);
	
	/**
	 * @param ciphertext the ciphertext
	 * @param publicKey	the public key
	 * @param secretKey the secret key
	 * @return return sucessful ? the decrypted load of the ciphertext : null
	 */
	byte[] decrypt(Ciphertext ciphertext , Key secretKey);
}
