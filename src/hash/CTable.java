package hash;

import java.security.PublicKey;
import java.util.Hashtable;

public class CTable 
{
	public Hashtable<String, CInfo> cTable;
	
	public void initial()
	{
		cTable = new Hashtable<String, CInfo>();
	}
	
	public void insert(String identifier, CInfo cInfo)
	{
		cTable.put(identifier, cInfo);
	}
	
	public void remove(String identifier)
	{
		cTable.remove(identifier);
	}
	
	public boolean contain(String identifier)
	{
		return cTable.containsKey(identifier);
	}
	
	public CInfo getInfo(String identifier)
	{
		return cTable.get(identifier);
	}
	
	public PublicKey getPublicKey(String identifier)
	{
		return cTable.get(identifier).getPublic();
	}
	
	public PublicKey getVerifyKey(String identifier)
	{
		return cTable.get(identifier).getVerification();
	}
}
