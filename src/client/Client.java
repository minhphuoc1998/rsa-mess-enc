package client;

import java.io.*;
import java.net.*;
import java.security.*;
import hash.CTable;
import protobuf.sSegment;
import rsa.Rsa;
import protobuf.SegmentPB.Segment;

import java.util.*;

import com.google.protobuf.TextFormat;

public class Client implements Runnable 
{
	
	public String host;
	public int port;
	public Socket socket;
	public DataInputStream dis;
	public DataOutputStream dos;
	public Scanner scn;
	public String identifier;
	public CTable cTable;
	public PrivateKey prikey;
	public PrivateKey sigkey;
	
	public Client(String host, int port)
	{
		// Set host, port
		this.host = host;
		this.port = port;
		
		// Initialize Client Table
		cTable = new CTable();
		cTable.initial();
		
		// Initialize Scanner
		scn = new Scanner(System.in);
	}
	
	public boolean connect()
	{
		// Initialize Socket
		try
		{
			socket = new Socket(host, port);
			dis = new DataInputStream(socket.getInputStream());
			dos = new DataOutputStream(socket.getOutputStream());
		}
		catch (IOException e)
		{
			e.printStackTrace();
			return false;
		}
		System.out.println("Initialize Socket success");
		
		// Request connect
		try
		{
			Segment requestConnect = sSegment.newSegmentRequestConnect();
			sendSegment(requestConnect);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return false;
		}
		System.out.println("Sent request connect");
		
		// Check agreement
		try
		{
			Segment rRequestConnect = receiveSegment();
			if (!sSegment.isAccept(rRequestConnect))
				return false;
			this.identifier = rRequestConnect.getIdentifier();
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return false;
		}
		System.out.println("Server accepted connection");
		
		// Generate public key
		PublicKey pubKey, verKey;
		String pubkey, verkey;
		
		try
		{
				// Generate Public Key and Private Key
			KeyPair firstKeyPair = Rsa.buildKeyPair();
			prikey = firstKeyPair.getPrivate();
			pubKey = firstKeyPair.getPublic();
			pubkey = Rsa.byteToString(pubKey.getEncoded());
				// Generate Signing Key and Verifying Key
			KeyPair secondKeyPair = Rsa.buildKeyPair();
			sigkey = secondKeyPair.getPrivate();
			verKey = secondKeyPair.getPublic();
			verkey = Rsa.byteToString(verKey.getEncoded());
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return false;
		}
		System.out.println("Generated key");
		
		// Send Send-Key segment
		try
		{
			// Create Send-Key segment
			Segment sendKey = sSegment.newSegmentSendKey(pubkey, verkey);
			// Send segment
			sendSegment(sendKey);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return false;
		}
		System.out.println("Sent key");
		
		// Receive and Check agreement
		try
		{
			// Receive reply from server
			Segment rSendKey = receiveSegment();
			// Check if server accepted
			if (sSegment.isAccept(rSendKey))
			{
				System.out.println("Server accepted connection request");
				return true;
			}
			System.out.println("Server rejected connection request");
			return false;	
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return false;
		}
	}
	
	public boolean getPublicKey(String identifier)
	{
		// Check in cTable
		if (cTable.contain(identifier))
			return true;
		
		// Get key from server
		if (getPublicKeyServer(identifier))
			return true;
		
		// No key available
		return false;
	}
	
	public boolean getPublicKeyServer(String identifier)
	{
		// Create request
		
		// Send request
		
		// Receive reply
		
		// Check reply
		
		// Insert into cTable
		
		
		return true;
	}
	
	public void sendSegment(Segment segment) throws Exception
	{
		dos.writeUTF(segment.toString());
	}
	
	public Segment receiveSegment() throws Exception
	{
		// Read message from dis
		String raw = dis.readUTF();
		
		// Create builder
		Segment.Builder _segment = Segment.newBuilder();
		
		// Parse message to builder
		TextFormat.getParser().merge(raw,  _segment);
		
		// Build segment
		Segment segment = _segment.build();
		
		return segment;
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		
	}
	
}
