package com.smartcard.encryption;

import junit.framework.TestCase;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PasswordBaseCipher extends TestCase
{
	private byte [] IV = new byte[] {8,7,6,5,4,3,2,1};
	private static char [] password = "test".toCharArray();
	 	
	public void testEncryptDecrypt() throws Exception
	{
		String dataToBeEncryptedString = new String("dataToBeEncrypted");
		
		ByteArrayInputStream bais = new ByteArrayInputStream(dataToBeEncryptedString.getBytes("ASCII"));
		ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
	
		//Şifreleme
		Cipher  encryptionCipher = createCipher(Cipher.ENCRYPT_MODE);
		applyCipher(bais, encryptedData, encryptionCipher);
		
		ByteArrayInputStream dataToBeDecrypted = new ByteArrayInputStream(encryptedData.toByteArray());
		ByteArrayOutputStream decryptedData = new ByteArrayOutputStream();

		//Şifre Çözme
		Cipher  decryptionCipher = createCipher(Cipher.DECRYPT_MODE);
		applyCipher(dataToBeDecrypted, decryptedData, decryptionCipher);
		
		
		String decryptedString = new String(decryptedData.toByteArray());
		
		assertEquals(dataToBeEncryptedString, decryptedString);
	}

	private Cipher createCipher(int mode) throws NoSuchAlgorithmException, InvalidKeySpecException,
										         NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException 
	{
		PBEKeySpec keySpec = new PBEKeySpec(password);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		SecretKey key = keyFactory.generateSecret(keySpec);

		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(IV);
		byte[] digest = md.digest();
		byte[] salt = new byte[8];
		for (int i = 0; i < 8; ++i)
			salt[i] = digest[i];
		PBEParameterSpec paramSpec = new PBEParameterSpec(salt, 20);
		Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
		cipher.init(mode, key, paramSpec);
		return cipher;
	} 

	private void applyCipher(InputStream inStream, OutputStream outStream, Cipher cipher) throws IOException 
	{
		CipherInputStream in = new CipherInputStream(inStream, cipher);
		BufferedOutputStream out = new BufferedOutputStream(outStream);
		int BUFFER_SIZE = 8;
		byte[] buffer = new byte[BUFFER_SIZE];
		int numRead = 0;
		do {
			numRead = in.read(buffer);
			if (numRead > 0)
				out.write(buffer, 0, numRead);
		} while (numRead == 8);
		out.close();
	}
}
