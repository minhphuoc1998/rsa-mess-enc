package server;

import java.io.*;
import java.net.*;
import java.security.*;

import com.google.protobuf.TextFormat;

import protobuf.sSegment;
import protobuf.SegmentPB.Segment;
import rsa.Rsa;
import hash.*;


public class ServiceThread implements Runnable
{
	public String identifier;
	public Socket socketOfServer;
	public DataInputStream dis;
	public DataOutputStream dos;
	
	public ServiceThread(Socket socketOfServer, String identifier) throws Exception
	{
		this.identifier = identifier;
		this.socketOfServer = socketOfServer;
		this.dis = new DataInputStream(this.socketOfServer.getInputStream());
		this.dos = new DataOutputStream(this.socketOfServer.getOutputStream());
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
//		System.out.println(segment.toString());
		return segment;
	}
	
	public boolean getPublicKey(String identifier) throws Exception
	{
		if (!Server.sTable.contain(identifier))
		{
			sendSegment(sSegment.newSegmentReject());
			return false;
		}
		
		PublicKey _pubkey = Server.sTable.getPublicKey(identifier);
		PublicKey _verkey = Server.sTable.getVerifyKey(identifier);
		
		String pubkey = Rsa.byteToString(_pubkey.getEncoded());
		String verkey = Rsa.byteToString(_verkey.getEncoded());
		
		Segment sendKey = sSegment.newSegmentSendKey(pubkey, verkey);
		sendSegment(sendKey);
		
		return true;
	}
	
	public void deliverSegment(Segment segment) throws Exception
	{
		String receiver = segment.getReceiver();
		
//		System.out.println(receiver);
		
		Socket socket = Server.sTable.getSocket(receiver);
		
		DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
//		System.out.println(segment.toString());
		dos.writeUTF(segment.toString());
	}
	
	@Override
	public void run() {
		// TODO Auto-generated method stub
		try
		{
			while (true)
			{
				if (dis.available() > 0)
				{
					Segment request = receiveSegment();
					System.out.println(request.toString());
					
					if (sSegment.isRequestKey(request))
					{
						getPublicKey(request.getIdentifier());
						continue;
					}
					
					deliverSegment(request);
				}
				
			}
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		finally
		{
			try
			{
				disconnect();
			}
			catch (Exception e)
			{
				e.printStackTrace();
			}
		}
	}
}
