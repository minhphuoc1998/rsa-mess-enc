package server;

import java.io.*;
import java.net.*;
import java.security.*;

import com.google.protobuf.TextFormat;
import hash.*;
import rsa.Rsa;

import protobuf.SegmentPB.Segment;
import protobuf.sSegment;

public class IdentifyThread implements Runnable
{
	public int clientNumber;
	String identifier;
	public Socket socketOfServer;
	public DataInputStream dis;
	public DataOutputStream dos;
	
	public IdentifyThread(Socket socketOfServer, int clientNumber) throws Exception
	{
		this.socketOfServer = socketOfServer;
		this.clientNumber = clientNumber;
		this.dis = new DataInputStream(this.socketOfServer.getInputStream());
		this.dos = new DataOutputStream(this.socketOfServer.getOutputStream());
		this.identifier = hash.Function.sha256(String.valueOf(clientNumber));
		
	}
	
	public void disconnect() throws Exception
	{
		Server.sTable.remove(identifier);
		socketOfServer.close();
		dis.close();
		dos.close();
	}
	
	public void sendSegment(Segment segment) throws Exception
	{
		dos.writeUTF(segment.toString());
	}
	
	public Segment receiveSegment() throws Exception
	{
		String raw = dis.readUTF();
		Segment.Builder _segment = Segment.newBuilder();
		TextFormat.getParser().merge(raw, _segment);
		Segment segment = _segment.build();
		
		return segment;
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		
		try
		{
			System.out.println("Begin authentication");
			// Receive request connect
			receiveSegment();
			// Send ID to client and request key
			sendSegment(sSegment.newSegmentAccept(identifier));
			
			System.out.println("Send request key to client: done");
			
			// Receive Key, get Key and put to table
			Segment keySegment = receiveSegment();
			System.out.println("Receive key from client: done");
			
			String _pubkey = keySegment.getPubkey();
			String _verkey = keySegment.getVerkey();
			PublicKey pubkey = Rsa.getPublicKey(Rsa.stringToByte(_pubkey));
			PublicKey verkey = Rsa.getPublicKey(Rsa.stringToByte(_verkey));
			
			SInfo info = new SInfo(pubkey, verkey, socketOfServer);
			
			Server.sTable.insert(identifier, info);
			System.out.println("Insert Key to Table: done");
			
			// Accept connection
			sendSegment(sSegment.newSegmentAccept());
			System.out.println("Send agreement to client: done");
			
			// Create ServiceThread
			System.out.println("Authentication finish, creating Service Thread");
			ServiceThread serviceThread = new ServiceThread(this.socketOfServer, this.identifier);
			Thread clientHandler = new Thread(serviceThread);
			clientHandler.start();
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		
	}
	

}
