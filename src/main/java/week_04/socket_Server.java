/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package week_04;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author khang
 */
public class socket_Server {
    private static final int PORT = 12345;
    public static void main(String[] args) {
        try{
            try (ServerSocket serverSocket = new ServerSocket(PORT)) {
                System.out.println("Server is running...");
                Socket socket = serverSocket.accept();
                System.out.println("Client connected.");
                
                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
                keyPairGen.initialize(1024);
                KeyPair serverKeyPair = keyPairGen.generateKeyPair();
                KeyAgreement serverKeyAgreement = KeyAgreement.getInstance("DiffieHellman");
                serverKeyAgreement.init(serverKeyPair.getPrivate());
                
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                out.writeObject(serverKeyPair.getPublic().getEncoded());
                
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                byte[] clientPublicKeyBytes = (byte[]) in.readObject();
                KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientPublicKeyBytes);
                PublicKey clientPublicKey = keyFactory.generatePublic(x509KeySpec);
                
                serverKeyAgreement.doPhase(clientPublicKey, true);
                
                byte[] sharedSecret = serverKeyAgreement.generateSecret();
                SecretKeySpec secretkeySpec = new SecretKeySpec(sharedSecret, 0, 16, "AES");
                
                byte[] encryptedBytes = (byte[]) in.readObject();
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, secretkeySpec);
                String decryptedMessage = new String(cipher.doFinal(encryptedBytes));
                System.out.println("Received message from client: " + new String(encryptedBytes));
                System.out.println("Decrypted message from client: " + decryptedMessage);
                
                socket.close();
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException
                | ClassNotFoundException | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException | InvalidKeySpecException ex) {
            ex.printStackTrace();
        }
    }
}
