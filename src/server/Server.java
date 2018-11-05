package server;

import java.io.*;
import java.net.*;
import java.security.*;

import hash.*;
import protobuf.sSegment;
import protobuf.SegmentPB.Segment;
import rsa.Rsa;
import java.util.*;

public class Server implements Runnable
{

	public ServerSocket listener;
	public static STable sTable;
	public static int clientNumber;
	public static int clientNumbers;
	public int port;
	
	public Server()
	{
		clientNumber = 0;
		clientNumbers = 0;
		sTable = new STable();
		sTable.initial();
		
		try
		{
			port = 5003;
			listener = new ServerSocket(port);
			
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}
	
	@Override
	public void run() {

		try
		{
			while (true)
			{
				clientNumber ++;
				clientNumbers ++;
				Socket socketOfServer = listener.accept();
				System.out.println("A new client is connected");
				
				// Identify Thread to get Key from client
				IdentifyThread identifyThread = new IdentifyThread(socketOfServer, clientNumber); 
				Thread identify = new Thread(identifyThread);
				identify.start();
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
				listener.close();
			}
			catch (Exception e)
			{
				e.printStackTrace();
			}
		}
		
		
	}
	
}
