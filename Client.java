
import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import java.security.spec.*;
import java.util.Date;
public class Client {
 public static void main(String[] args) {
 if (args.length != 3) {
 System.out.println("Usage: java Client host port userid");
return;
 }
 String host = args[0];
 int port = Integer.parseInt(args[1]);
 String userid = args[2];
 try {
 Socket socket = new Socket(host, port);
 ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
 ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
 // Sending hashed userid to the server
String hashedUserID = hashUserID(userid);
 out.writeObject(hashedUserID);
 out.flush();
 // Receiving number of messages for this user
int numMessages = (int) in.readObject();
 if (numMessages == 0) {
 System.out.println("There are 0 message(s) for you.");
 } else {
 // Handling received messages
System.out.println("There are " + numMessages + " message(s) for you.");
 for (int i = 0; i < numMessages; i++) {
 byte[] encryptedMessage = (byte[]) in.readObject();
 Date timestamp = (Date) in.readObject();
 byte[] signature = (byte[]) in.readObject();
 // Verifying signature
PublicKey senderPublicKey = readPublicKey("server.pub");
 if (verifySignature(encryptedMessage, timestamp, signature, senderPublicKey)) {
 // Decrypting message
String decryptedMessage = decrypt(encryptedMessage, readPrivateKey(userid + ".prv"));
 System.out.println("Date: " + timestamp);
 System.out.println("Message: " + decryptedMessage);
 } else {
 socket.close(); // Client connection terminated
 }
 }
 }
 System.out.println("Do you want to send a message? [y/n]");
BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
 String choice = reader.readLine();
if (choice.equalsIgnoreCase("y")) {
 System.out.println("Enter the recipient userid:");
String recipient = reader.readLine();
System.out.println("Enter your message:");
String message = reader.readLine();
String padRecipient = recipient + " ";
 // Concatenate recipient userid with the message
String altMessage = padRecipient + message;
 // Encrypting the message
 PublicKey serverPublicKey = readPublicKey("server.pub");
 byte[] encryptedMessage = encrypt(altMessage, serverPublicKey);
 // Creating timestamp
Date timestamp = new Date();
 // Creating signature
File f = new File(userid + ".prv");
 if (!f.exists())
 socket.close();
 PrivateKey privateKey = readPrivateKey(userid + ".prv");
 byte[] signature = signMessage(encryptedMessage, timestamp, privateKey);
 // Sending encrypted message, timestamp, signature, and sender(Not recipient)
// userid to server
 out.writeObject(encryptedMessage);
 out.writeObject(timestamp);
 out.writeObject(signature);
 out.writeObject(userid);
 out.flush();
 } else {
 socket.close();
 }
 } catch (Exception e) {
 System.out.println("Client connection terminated.");
 }
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
 private static PrivateKey readPrivateKey(String filename)
 throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
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
 private static byte[] signMessage(byte[] data, Date timestamp, PrivateKey key)
 throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
 Signature signer = Signature.getInstance("SHA256withRSA");
 signer.initSign(key);
 signer.update(data);
 signer.update(timestamp.toString().getBytes());
 return signer.sign();
 }
 private static boolean verifySignature(byte[] data, Date timestamp, byte[] signature, PublicKey key)
 throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
 Signature verifier = Signature.getInstance("SHA256withRSA");
 verifier.initVerify(key);
 verifier.update(data);
 verifier.update(timestamp.toString().getBytes());
 return verifier.verify(signature);
 }
}