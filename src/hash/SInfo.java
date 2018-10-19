package hash;

import java.net.Socket;
import java.security.PublicKey;

public class SInfo 
{
	PublicKey pubkey;
	PublicKey verkey;
	Socket socket;
	int vec;
	
	public SInfo(PublicKey pubkey, PublicKey verkey, Socket socket)
	{
		this.pubkey = pubkey;
		this.verkey = verkey;
		this.socket = socket;
	}
	
	public PublicKey getPublic()
	{
		return this.pubkey;
	}
	
	public PublicKey getVerification()
	{
		return this.verkey;
	}
	
	public Socket getSocket()
	{
		return this.socket;
	}
	
}
