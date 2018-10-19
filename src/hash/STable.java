package hash;

import java.net.Socket;
import java.security.PublicKey;
import java.util.Hashtable;

public class STable 
{
	public Hashtable<String, SInfo> sTable;
	
	public void initial()
	{
		sTable = new Hashtable<String, SInfo>();
	}
	
	public void insert(String identifier, SInfo sInfo)
	{
		sTable.put(identifier, sInfo);
	}
	
	public void remove(String identifier)
	{
		sTable.remove(identifier);
	}
	
	public boolean contain(String identifier)
	{
		return sTable.containsKey(identifier);
	}
	
	public SInfo getInfo(String identifier)
	{
		return sTable.get(identifier);
	}
	
	public PublicKey getPublicKey(String identifier)
	{
		return sTable.get(identifier).getPublic();
	}
	
	public PublicKey getVerifyKey(String identifier)
	{
		return sTable.get(identifier).getVerification();
	}
	
	public Socket getSocket(String identifier)
	{
		return sTable.get(identifier).getSocket();
	}
}
