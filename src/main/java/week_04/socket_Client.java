/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package week_04;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
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
public class socket_Client {
    private static final String SERVER_IP = "127.0.0.1";
    private static final int PORT = 12345;
    
    public static void main(String[] args) {
        try {
            try (Socket socket = new Socket(SERVER_IP, PORT)) {
                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
                keyPairGen.initialize(1024);
                KeyPair clientKeyPair = keyPairGen.genKeyPair();
                KeyAgreement clientKeyAgreement = KeyAgreement.getInstance("DiffieHellman");
                clientKeyAgreement.init(clientKeyPair.getPrivate());
                
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
                byte[] serverPublicKeyBytes = (byte[]) in.readObject();
                KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(serverPublicKeyBytes);
                PublicKey serverPublicKey = keyFactory.generatePublic(x509KeySpec);
                clientKeyAgreement.doPhase(serverPublicKey, true);
                out.writeObject(clientKeyPair.getPublic().getEncoded());
                
                byte[] sharedSecret = clientKeyAgreement.generateSecret();
                SecretKeySpec secretKeySpec = new SecretKeySpec(sharedSecret, 0, 16, "AES");
                
                Scanner scanner = new Scanner(System.in);
                System.out.print("Enter tetx: ");
                String plaintext = scanner.nextLine();
                
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
                byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
                out.writeObject(encryptedBytes);
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException
                | ClassNotFoundException | NoSuchPaddingException | IllegalBlockSizeException
                | BadPaddingException | InvalidKeySpecException ex) {
            ex.printStackTrace();
        }
    }
}
