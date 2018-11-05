package client;

public class testClient 
{
	public static void main(String[] args) throws Exception
	{
		String ip = "35.220.137.70";
		Client client = new Client(ip, 5003);
		
		System.out.println(client.connect());
		client.run();
		
	}
}
