
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javafx.util.Pair;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
public class Server {
 public static void main(String[] args) {
 if (args.length != 1) {
 System.out.println("Usage: java Server port");
return;
 }
 
 int port = Integer.parseInt(args[0]);
 try {
 ServerSocket serverSocket = new ServerSocket(port);
 System.out.println("Server started. Listening on port " + port + "...");
 // Declares a Hashmap storage
HashMap<String, ArrayList<Pair<byte[], Date>>> storage = new HashMap<String, ArrayList<Pair<byte[], Date>>>();
 while (true) {
 Socket clientSocket = serverSocket.accept();
 ObjectInputStream in = new ObjectInputStream(clientSocket.getInputStream());
 ObjectOutputStream out = new ObjectOutputStream(clientSocket.getOutputStream());
 // Receiving hashed userid from client
String hashedUserID = (String) in.readObject();
 System.out.println("Client: " + hashedUserID + " logged in.");
 int numMessages = 0;
 if (storage.containsKey(hashedUserID)) {
 numMessages = storage.get(hashedUserID).size();
 }
 if (numMessages != 0)
 System.out.println("Delivering " + numMessages + " message(s)...");
 // Sending number of messages for this user
 out.writeObject(numMessages);
 out.flush();
 // Sending messages to the client
for (int i = 0; i < numMessages; i++) {
 byte[] encryptedMessage = storage.get(hashedUserID).get(i).getKey();
Date timestamp = storage.get(hashedUserID).get(i).getValue();
 out.writeObject(encryptedMessage);
 out.writeObject(timestamp);
 // Creating signature
PrivateKey privateKey = readPrivateKey("server.prv");
 byte[] signature = signMessage(encryptedMessage, timestamp, privateKey);
 out.writeObject(signature);
 }
 if (numMessages > 0) {
 storage.remove(hashedUserID);
 }
 else
 out.flush();
 // handling received new messages from client
try {
 byte[] encryptedMessageFromClient = (byte[]) in.readObject();
 Date timestampFromClient = (Date) in.readObject();
 byte[] signatureFromClient = (byte[]) in.readObject();
 String senderUserID = in.readObject().toString();
System.out.println("Incoming message from " + senderUserID);
 File f1 = new File(senderUserID + ".pub");
 if (!f1.exists())
 continue;
 PublicKey senderPublicKey = readPublicKey(senderUserID + ".pub");
 // Message decryption and storage are only allowed if userid is authorised by
// server and the signature can be verified
if (verifySignature(encryptedMessageFromClient, timestampFromClient, signatureFromClient,
 senderPublicKey)) {
 // Decrypting message
String decryptedMessage = decrypt(encryptedMessageFromClient, readPrivateKey("server.prv"));
 int recipientNameLen = decryptedMessage.indexOf(" ");
 String message = decryptedMessage.substring(recipientNameLen + 1);
 String recipientID = decryptedMessage.substring(0, recipientNameLen);
 System.out.println("Message received from sender " + senderUserID);
 System.out.println("Recipient id: " + recipientID);
 System.out.println("Message: " + message);
 File f2 = new File(recipientID + ".pub");
 if (!f2.exists())
 continue;
 PublicKey recipientPublicKey = readPublicKey(recipientID + ".pub");
 byte[] encryptedMessage = encrypt(message, recipientPublicKey);
String hashedRecipientUserID = hashUserID(decryptedMessage.substring(0, recipientNameLen));
 // updates the storage
if (!storage.containsKey(hashedRecipientUserID)) {
 storage.put(hashedRecipientUserID, new ArrayList<Pair<byte[], Date>>());
 }
 storage.get(hashedRecipientUserID).add(new Pair<>(encryptedMessage, timestampFromClient));
 }
 } catch (EOFException e) {
 System.out.println("No incoming message.");
 }
 clientSocket.close();
 }
 } catch (FileNotFoundException f) {
 System.out.println("Unauthorised userid");
 } catch (Exception e) {
 e.printStackTrace();
 }
 }
 private static PublicKey readPublicKey(String filename)
 throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
 FileInputStream fis = new FileInputStream(filename);
 byte[] encodedPublicKey = new byte[fis.available()];
 fis.read(encodedPublicKey);
 fis.close();
 X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(encodedPublicKey);
 KeyFactory kf = KeyFactory.getInstance("RSA");
 return kf.generatePublic(pubSpec);
 }
 private static boolean verifySignature(byte[] data, Date timestamp, byte[] signature, PublicKey key)
 throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
 Signature verifier = Signature.getInstance("SHA256withRSA");
 verifier.initVerify(key);
 verifier.update(data);
 verifier.update(timestamp.toString().getBytes());
 return verifier.verify(signature);
 }
 private static PrivateKey readPrivateKey(String filename)
 throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
 FileInputStream fis = new FileInputStream(filename);
 byte[] encodedPrivateKey = new byte[fis.available()];
 fis.read(encodedPrivateKey);
 fis.close();
 PKCS8EncodedKeySpec prvSpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
 KeyFactory kf = KeyFactory.getInstance("RSA");
 return kf.generatePrivate(prvSpec);
 }
 private static byte[] encrypt(String plaintext, PublicKey key) throws NoSuchAlgorithmException, BadPaddingException,
 NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
 Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
 cipher.init(Cipher.ENCRYPT_MODE, key);
 return cipher.doFinal(plaintext.getBytes());
 }
 private static String decrypt(byte[] ciphertext, PrivateKey key) throws NoSuchAlgorithmException,
 BadPaddingException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
 Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
 cipher.init(Cipher.DECRYPT_MODE, key);
 return new String(cipher.doFinal(ciphertext));
 }
 private static String hashUserID(String userid) throws NoSuchAlgorithmException {
 final String secret = "gfhk2024:";
 String data = secret + userid;
 MessageDigest md = MessageDigest.getInstance("MD5");
 byte[] hashBytes = md.digest(data.getBytes());
 return bytesToHex(hashBytes);
 }
 private static String bytesToHex(byte[] hash) {
 StringBuilder sb = new StringBuilder();
 for (byte b : hash)
 sb.append(String.format("%02X", b));
 return sb.toString();
 }
 private static byte[] signMessage(byte[] data, Date timestamp, PrivateKey key)
 throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
 Signature signer = Signature.getInstance("SHA256withRSA");
 signer.initSign(key);
 signer.update(data);
 signer.update(timestamp.toString().getBytes());
 return signer.sign();
 }
}