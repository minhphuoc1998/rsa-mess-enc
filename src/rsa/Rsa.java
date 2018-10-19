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

import protobuf.sSegment;
import protobuf.SegmentPB.Segment;
import client.Client;

public class Rsa 
{
	public static void main(String[] args) throws Exception
	{
		KeyPair s = buildKeyPair();
		PublicKey t = s.getPublic();
		PrivateKey z = s.getPrivate();
		
		KeyPair q = buildKeyPair(2176);
		PublicKey w = q.getPublic();
		PrivateKey r = q.getPrivate();
		
		String a = "conbocuoi";
		byte[] b = a.getBytes();
		byte[] c = encrypt(t, b);
		String d = byteToString(c);
		
		Segment sm = sSegment.newSegmentSendMessage("1", "2", "conbocuoi", t, r);
		
		String enc = sm.getData();
		
		byte[] e = stringToByte(enc);
		byte[] f = decrypt(z, e);
		String g = String.valueOf(f);
		System.out.println(f[0]);
		System.out.println(f[1]);
		System.out.println(f[2]);
		System.out.println(f[3]);
		System.out.println(f[4]);
		System.out.println(f[5]);
		

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
        
        return cipher.doFinal(Rsa.stringToByte(encrypted));
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
}
