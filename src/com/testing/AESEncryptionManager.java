package com.testing;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AESEncryptionManager {

	public static void main(String[] args) throws Exception {
		String file = "testing.csv";
		String password = "amod";

		// Encrypt file
		byte[] inputFileBytes = readFile(file);
		byte[] encryptedBytes = encryptData(password, inputFileBytes);
		String encrytedFileName = "aesgcm_encrypted_01_09_2023";
		writeFile(encrytedFileName, encryptedBytes);
		System.out.println("File encrypted");

		// Decrypt file

		byte[] encryptedFileBytes = readFile(encrytedFileName);
		byte[] decryptedFileBytes = decryptData(password, encryptedFileBytes);
		String decryptedFileName = "aesgcm_decrupted_01_09_2023";
		writeFile(decryptedFileName, decryptedFileBytes);
		System.out.println("File decrypted");
	}

	private static byte[] decryptData(String password, byte[] encryptedData)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		// wrap the data into ta byte buffer to ease the reading process
		ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);

		byte[] salt = new byte[8];
		byteBuffer.get(salt);

		byte[] iv = new byte[12];
		byteBuffer.get(iv);

		// Prepare your key/password
		SecretKey secretKey = generateSecretKey(password, salt);

		// get the rest of encrypted data
		int size = byteBuffer.remaining() - 16;
		byte[] cipherBytes = new byte[size];
		byteBuffer.get(cipherBytes);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);

		// Encryption mode is on!
		cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

		return cipher.doFinal(cipherBytes);
	}

	private static void writeFile(String path, byte[] data) throws IOException {
		try (FileOutputStream fileOutputStream = new FileOutputStream(path)) {
			fileOutputStream.write(data);
		}

	}

	private static byte[] encryptData(String password, byte[] data)
			throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		
		SecureRandom secureRandom = new SecureRandom();

		// salt - 8 bytes
		byte[] salt = new byte[8];
		secureRandom.nextBytes(salt);

		// iv - 12 bytes
		byte[] iv = new byte[12];
		secureRandom.nextBytes(iv);

		// prepare your key/password
		SecretKey secretKey = generateSecretKey(password, salt);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

		// Encrypt the data
		byte[] encryptedData = cipher.doFinal(data);

		// Tag - 16 bytes
		byte[] tag = new byte[16];
		secureRandom.nextBytes(tag);

		// Concatenate everything and return the final data
		ByteBuffer byteBuffer = ByteBuffer.allocate(salt.length + iv.length + encryptedData.length + tag.length);
		byteBuffer.put(salt);
		byteBuffer.put(iv);
		byteBuffer.put(encryptedData);
		byteBuffer.put(tag);
		return byteBuffer.array();
	}

	/**
	 * Function to generate a 256 bit key from the given password and salt
	 * 
	 * @param password
	 * @param salt
	 * @return
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	private static SecretKey generateSecretKey(String password, byte[] iv)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		KeySpec keySpec = new PBEKeySpec(password.toCharArray(), iv, 10000, 256);
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		byte[] key = secretKeyFactory.generateSecret(keySpec).getEncoded();
		return new SecretKeySpec(key, "AES");
	}

	private static byte[] readFile(String path) throws IOException {
		File file = new File(path);
		byte[] fileData = new byte[(int) file.length()];
		try (FileInputStream fileInputStream = new FileInputStream(file)) {
			fileInputStream.read(fileData);
		}
		return fileData;
	}

}
