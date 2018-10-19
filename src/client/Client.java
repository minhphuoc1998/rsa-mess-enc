package client;

import java.io.*;
import java.net.*;
import java.security.*;

import hash.*;
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
			KeyPair firstKeyPair = Rsa.buildKeyPair(2048);
			prikey = firstKeyPair.getPrivate();
			pubKey = firstKeyPair.getPublic();
			pubkey = Rsa.byteToString(pubKey.getEncoded());
				// Generate Signing Key and Verifying Key
			KeyPair secondKeyPair = Rsa.buildKeyPair(2176);
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
	
	public boolean getPublicKey(String identifier) throws Exception
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
	
	public boolean getPublicKeyServer(String identifier) throws Exception
	{
		// Create request
		Segment requestKey = sSegment.newSegmentRequestKey(identifier);
		
		// Send request
		sendSegment(requestKey);
		
		// Receive reply
		Segment rRequestKey = receiveSegment();
		
		// Check reply
		if (!sSegment.isSendKey(rRequestKey))
		{
			return false;
		}
		
		// Get pubkey, verkey
		String _pubkey = rRequestKey.getPubkey();
		String _verkey = rRequestKey.getVerkey();
		PublicKey pubkey = Rsa.getPublicKey(Rsa.stringToByte(_pubkey));
		PublicKey verkey = Rsa.getPublicKey(Rsa.stringToByte(_verkey));
		
		// Insert into cTable
		CInfo info = new CInfo(pubkey, verkey);
		cTable.insert(identifier, info);
		
		return true;
	}
	
	public boolean sendMessage(String identifier, String message) throws Exception
	{
		// Get pubkey
		if (!getPublicKey(identifier))
			return false;
		
		PublicKey pubkey = cTable.getPublicKey(identifier);
		
		System.out.println("sendMessage: got public key");
		
		// Split message
		String[] messages = Rsa.splitMessage(message);
		int length = messages.length;
		
		System.out.println("sendMessage: split message");
		
		// Create Request Segment
		Segment requestSendMessage = sSegment.newSegmentRequestSendMessage(this.identifier, identifier, String.valueOf(length));
		
		// Send Request Segment
		sendSegment(requestSendMessage);
		
		System.out.println("sendMessage: send request");
		
		// Receive Agreement
		Segment rRequestSendMessage = receiveSegment();
		if (!sSegment.isAccept(rRequestSendMessage))
			return false;
		
		System.out.println("sendMessage: received agreement");
		
		// Send Messages
		for (int i = 0; i < length; i ++)
		{
			// Create segment i
			Segment sendMess = sSegment.newSegmentSendMessage(this.identifier, identifier, messages[i], pubkey, sigkey);
		
			// Send segment i
			sendSegment(sendMess);
			
			// Receive message
			
			while (true)
			{
				Segment rSendMess = receiveSegment();
				
				// Check Error
				if (sSegment.isNext(rSendMess))
					break;
				else if (sSegment.isError(rSendMess))
					sendSegment(sendMess);
				else
					return false;
			}
		}
		return true;
	}
	
	public String receiveMessage(String identifier, int length) throws Exception
	{
		// Get VerKey
		if (!getPublicKey(identifier))
		{
			sendSegment(sSegment.newSegmentReject(this.identifier, identifier));
			return null;
		}
		PublicKey verkey = cTable.getVerifyKey(identifier);
		
		// Accept message
		sendSegment(sSegment.newSegmentAccept(this.identifier, identifier));
		
		String result = "";
		// Receive message
		for (int i = 0; i < length; i ++)
		{
			Segment received = receiveSegment();
			// check sum
			if (!checksum(received))
			{
				sendSegment(sSegment.newSegmentError(this.identifier, identifier));
				continue;
			}
			else if (!verify(verkey, received))
			{
				continue;
			}
			else
			{
				String encrypted = received.getData();
				byte[] decrypted = Rsa.decrypt(prikey, encrypted);
				String mess = new String(decrypted);
				result += mess;
				sendSegment(sSegment.newSegmentNext(this.identifier, identifier));
			}
		}

		return result;
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

	public boolean verify(PublicKey verkey, Segment segment) throws Exception
	{
		String message = segment.getData();
		String signature = segment.getSignature();
		
		byte[] _message = Rsa.stringToByte(message);
		byte[] _signature = Rsa.stringToByte(signature);
		byte[] _verification = Rsa.verify(verkey, _signature);
		if (Rsa.checkEquals(_message, _verification, _message.length))
			return true;
		return false;
	}
	
	public boolean checksum(Segment segment) throws Exception
	{
		String data = segment.getData();
		
		String dchecksum = segment.getDchecksum();
		String _dchecksum = Function.checksum(data).toString();
		if (!_dchecksum.equals(dchecksum))
			return false;
		
		String signature = segment.getSignature();
		
		String schecksum = segment.getSchecksum();
		String _schecksum = Function.checksum(signature).toString();
		if (!_schecksum.equals(schecksum))
			return false;
		return true;
	}
	
	@Override
	public void run() {

		try
		{
			@SuppressWarnings("resource")
			Scanner scn = new Scanner(System.in);
			System.out.println(identifier);
			while (true)
			{
				String cmd = scn.nextLine();
				if (cmd.equals("send"))
				{
					System.out.println("Receiver: ");
					String receiver = scn.nextLine();
					
					System.out.println("Message: ");
					String message = scn.nextLine();
					
					sendMessage(receiver, message);
				}
				else if (cmd.equals("key"))
				{
					System.out.println("identifier");
					String id = scn.nextLine();
					System.out.println(getPublicKey(id));
				}
				
				if (dis.available() > 0)
				{
					Segment received = receiveSegment();
					System.out.println(received.toString());
					if (sSegment.isRequestSendMessage(received))
					{
						String identifier = received.getSender();
						int length = Integer.parseInt(received.getLength());
						
						String mess = receiveMessage(identifier, length);
						System.out.println(mess);
					}
				}
			}
			
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		
	}
	
}
