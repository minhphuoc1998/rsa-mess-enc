package rsa;

import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;

import protobuf.sSegment;
import protobuf.SegmentPB.Segment;
import client.Client;

public class Rsa 
{
	public static void main(String[] args) throws Exception
	{
		KeyPair a = buildKeyPair();
		PublicKey pub = a.getPublic();
		PrivateKey pri = a.getPrivate();
		System.out.println(getString(pub));
		System.out.println(pri.toString());
		
	}
	
	public static int BLOCK_SIZE = 240;
	
    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);      
        return keyPairGenerator.genKeyPair();
    }

    public static KeyPair buildKeyPair(int length) throws NoSuchAlgorithmException {
        final int keySize = length;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);      
        return keyPairGenerator.genKeyPair();
    }
    
    public static byte[][] splitMessage(byte[] message)
    {
    	byte[][] messages = new byte[(message.length + BLOCK_SIZE - 1) / BLOCK_SIZE][BLOCK_SIZE];
    	
    	for (int i = 0; i < message.length; i ++)
    	{
    		messages[i / BLOCK_SIZE][i % BLOCK_SIZE] = message[i];
    	}
    	
    	return messages;
    }
    
    public static String[] splitMessage(String message)
    {
    	String[] messages = new String[(message.length() + BLOCK_SIZE - 1) / BLOCK_SIZE];
    	
    	int index = 0, i = 0;
    	while (index < message.length())
    	{
    		messages[i] = message.substring(index, Math.min(index + BLOCK_SIZE, message.length()));
    		index += BLOCK_SIZE;
    		i ++;
    	}
		return messages;
    }
    
    public static byte[] sign(PrivateKey signingKey, byte[] message) throws Exception {
    	Cipher cipher = Cipher.getInstance("RSA");
    	cipher.init(Cipher.ENCRYPT_MODE, signingKey);
    	
    	return cipher.doFinal(message);
    }
    
    public static byte[] verify(PublicKey verifyingkey, byte[] message) throws Exception {
    	Cipher cipher = Cipher.getInstance("RSA");
    	cipher.init(Cipher.DECRYPT_MODE, verifyingkey);
    	
    	return cipher.doFinal(message);
    }
    
    public static byte[] encrypt(PublicKey publicKey, byte[] message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);  

        return cipher.doFinal(message);  
    }
    
    public static byte[] decrypt(PrivateKey privateKey, String encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        return cipher.doFinal(Rsa.decode(encrypted));
    }

    public static byte[] decrypt(PrivateKey privateKey, byte [] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");  
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        return cipher.doFinal(encrypted);
    }
    
    public static PublicKey getPublicKey(byte[] encodedKey) throws Exception
    {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(encodedKey);
        return factory.generatePublic(encodedKeySpec);
    }
    
    public static String byteToString(byte[] b)
    {
    	String result = String.valueOf(b[0]);
    	
    	for (int i = 1; i < b.length; i ++)
    	{
    		result += " " + String.valueOf(b[i]);
    	}
    	
    	return result;
    }

    public static byte[] stringToByte(String s)
    {
    	String[] _s = s.split(" ");
    	byte[] b = new byte[_s.length];
    	for (int i = 0; i < _s.length; i ++)
    	{
    		b[i] = (byte) Integer.parseInt(_s[i]);
    	}
    	return b;
    	
    }
    
    public static String encode(byte[] b)
    {
    	byte[] encodedBytes = Base64.getEncoder().encode(b);
    	return new String(encodedBytes);
    }
    
    public static byte[] decode(String s)
    {
    	byte[] decodedBytes = Base64.getDecoder().decode(s.getBytes());
    	return decodedBytes;
    }
    
    public static boolean checkEquals(byte[] a, byte[] b)
    {
    	if (a.length != b.length)
    		return false;
    	for (int i = 0; i < a.length; i ++)
    	{
    		if (a[i] != b[i])
    			return false;
    	}
    	return true;
    }
    
    public static boolean checkEquals(byte[] a, byte[] b, int length)
    {
    	for (int i = 0; i < length; i ++)
    	{
    		if (a[i] != b[i])
    			return false;
    	}
    	return true;
    }
    
    public static String getString(PublicKey pubkey)
    {
    	int block = 90;
    	String ans = "";
    	String s = pubkey.toString();
    	int modi = s.indexOf("modulus: ");
    	int expi = s.indexOf("public exponent: ");
    	String s1 = s.substring(0, modi).trim();
    	String s2 = s.substring(modi, expi).trim();
    	String s3 = s.substring(expi).trim();
    	
    	String[] s2s = new String[(s2.length() + block - 1) / block];
    	
    	for (int i = 0; i < (s2.length() + block - 1) / block; i ++)
    	{
    		s2s[i] = s2.substring(i * block, Math.min((i + 1) * block, s2.length()));
    	}
    	ans += s1 + "\n";
    	for (int i = 0; i < s2s.length; i ++)
    	{
    		ans += s2s[i] + "\n";
    	}
    	ans += s3;
    	return ans;
    }
}
