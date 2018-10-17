package hash;

import java.security.PublicKey;

public class CInfo 
{
	PublicKey pubkey;
	PublicKey verkey;
	
	public CInfo(PublicKey pubkey, PublicKey verkey)
	{
		this.pubkey = pubkey;
		this.verkey = verkey;
	}
	
	public PublicKey getPublic()
	{
		return pubkey;
	}
	
	public PublicKey getVerification()
	{
		return verkey;
	}
}
