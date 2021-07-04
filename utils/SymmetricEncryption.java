package utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import java.io.IOException;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;


public class SymmetricEncryption {

	
	public KeyGenerator keyGen (byte[] strKey) {  
        try {  
        	KeyGenerator kgen = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");  
            secureRandom.setSeed(strKey);  
            kgen.init(128, secureRandom);
            return kgen;
        } catch (Exception e) {  
            throw new RuntimeException(  
                    "Error setting key. Cause: " + e);  
        }  
    }
	
	public byte[] encrypt(byte[] content, byte[] encryptKey) throws Exception {
		
		KeyGenerator kgen = this.keyGen(encryptKey);
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kgen.generateKey().getEncoded(), "AES"));
		return cipher.doFinal(content);
	}

	public byte[] decrypt(byte[] sourceBytes, byte[] decryptKey) throws Exception {
		
		byte[] clearBytes = null;
		ByteArrayInputStream inputStream = null;
		ByteArrayOutputStream outputStream = null;
		try {
					
			// init AES
			KeyGenerator kgen = this.keyGen(decryptKey);
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kgen.generateKey().getEncoded(), "AES"));
			
			inputStream = new ByteArrayInputStream(sourceBytes);
			outputStream = new ByteArrayOutputStream();
			CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
			byte[] buffer = new byte[51200];   //50MB
			int r;
			while ((r = inputStream.read(buffer)) >= 0) {
				cipherOutputStream.write(buffer, 0, r);
			}
			cipherOutputStream.close();
			clearBytes = outputStream.toByteArray();
		} catch (IOException e) {
			e.printStackTrace(); // To change body of catch statement use File |
									// Settings | File Templates.
		} finally {
			try {
				inputStream.close();
			} catch (IOException e) {
				e.printStackTrace(); // To change body of catch statement use
										// File | Settings | File Templates.
			}
			try {
				outputStream.close();
			} catch (IOException e) {
				e.printStackTrace(); // To change body of catch statement use
										// File | Settings | File Templates.
			}
		}
		return clearBytes;
	}


}
