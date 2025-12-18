/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package week_03;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author khang
 */
public class RSA_AES_Cipher {
    private PublicKey publicKey;
    private PrivateKey privateKey;
    
    public RSA_AES_Cipher() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }
    
    public byte[] encrypt(String plaintext) throws Exception {
        SecretKey secretKey = generateAESKey();
        byte[] encryptedSymmetricKey = rsaEncrypt(secretKey.getEncoded());
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = aesCipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] combined = new byte[encryptedSymmetricKey.length + encryptedData.length];
        System.arraycopy(encryptedSymmetricKey, 0, combined, 0, encryptedSymmetricKey.length);
        System.arraycopy(encryptedData, 0, combined, encryptedSymmetricKey.length, encryptedData.length);
        return combined;
    }
    
    public String decrypt(byte[] combined) throws Exception{
        int symmetricKeyLenght = 256;
        byte[] encryptedSymmetricKey = new byte[symmetricKeyLenght];
        byte[] encryptedData = new byte[combined.length - symmetricKeyLenght];
        System.arraycopy(combined, 0, encryptedSymmetricKey, 0, symmetricKeyLenght);
        System.arraycopy(combined, symmetricKeyLenght, encryptedData, 0, encryptedData.length);
        byte[] decryptedSymmetricKey = rsaDecrypt(encryptedSymmetricKey);
        SecretKey secretKey = new SecretKeySpec(decryptedSymmetricKey, "AES");
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedData = aesCipher.doFinal(encryptedData);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }
    
    private SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }
    
    private byte[] rsaEncrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }
    
    private byte[] rsaDecrypt(byte[] encryptdData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        return cipher.doFinal(encryptdData);
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }
    
    
}
