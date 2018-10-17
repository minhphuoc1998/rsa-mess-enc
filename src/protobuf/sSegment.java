package protobuf;

import protobuf.SegmentPB.Segment;

import java.security.PrivateKey;
import java.security.PublicKey;

import rsa.Rsa;
import hash.Function;

public class sSegment 
{
	public static Segment newSegmentNext(String sender, String receiver)
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.NEXT);
		_segment.setSender(sender);
		_segment.setReceiver(receiver);
		_segment.setData("0");
		_segment.setDchecksum("0");
		_segment.setSignature("0");
		_segment.setSchecksum("0");
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
	}
	
	public static Segment newSegmentError(String sender, String receiver)
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.ERROR);
		_segment.setSender(sender);
		_segment.setReceiver(receiver);
		_segment.setData("0");
		_segment.setDchecksum("0");
		_segment.setSignature("0");
		_segment.setSchecksum("0");
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
	}
	
	public static Segment newSegmentAccept(String sender, String receiver)
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.ACCEPT);
		_segment.setSender(sender);
		_segment.setReceiver(receiver);
		_segment.setData("0");
		_segment.setDchecksum("0");
		_segment.setSignature("0");
		_segment.setSchecksum("0");
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
	}
	
	public static Segment newSegmentReject(String sender, String receiver)
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.REJECT);
		_segment.setSender(sender);
		_segment.setReceiver(receiver);
		_segment.setData("0");
		_segment.setDchecksum("0");
		_segment.setSignature("0");
		_segment.setSchecksum("0");
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
	}
	
	public static Segment newSegmentAccept()
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.ACCEPT);
		_segment.setSender("0");
		_segment.setReceiver("1");
		_segment.setData("0");
		_segment.setDchecksum("0");
		_segment.setSignature("0");
		_segment.setSchecksum("0");
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
	}
	
	public static Segment newSegmentAccept(String identifier)
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.ACCEPT);
		_segment.setSender("0");
		_segment.setReceiver("1");
		_segment.setData("0");
		_segment.setDchecksum("0");
		_segment.setSignature("0");
		_segment.setSchecksum("0");
		_segment.setIdentifier(identifier);
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
	}
	
	public static Segment newSegmentReject()
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.REJECT);
		_segment.setSender("0");
		_segment.setReceiver("1");
		_segment.setData("0");
		_segment.setDchecksum("0");
		_segment.setSignature("0");
		_segment.setSchecksum("0");
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
	}
	
	public static Segment newSegmentRequestConnect()
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.REQUEST_CONNECT);
		_segment.setSender("0");
		_segment.setReceiver("1");
		_segment.setData("0");
		_segment.setDchecksum("0");
		_segment.setSignature("0");
		_segment.setSchecksum("0");
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
	}
	
	public static Segment newSegmentDisconnect(String identifier)
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.DISCONNECT);
		_segment.setSender("0");
		_segment.setReceiver("1");
		_segment.setData("0");
		_segment.setDchecksum("0");
		_segment.setSignature("0");
		_segment.setSchecksum("0");
		_segment.setIdentifier(identifier);
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
	}
	
	public static Segment newSegmentRequestKey(String identifier)
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.REQUEST_KEY);
		_segment.setSender("0");
		_segment.setReceiver("1");
		_segment.setData("0");
		_segment.setDchecksum("0");
		_segment.setSignature("0");
		_segment.setSchecksum("0");
		_segment.setIdentifier(identifier);
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
	}
	
	public static Segment newSegmentSendKey(String pubkey, String verkey)
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.SEND_KEY);
		_segment.setSender("0");
		_segment.setReceiver("1");
		_segment.setData("0");
		_segment.setDchecksum("0");
		_segment.setSignature("0");
		_segment.setSchecksum("0");
		
		_segment.setPubkey(pubkey);
		_segment.setVerkey(verkey);
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
	}
	
	public static Segment newSegmentSendMessage(String sender, String receiver, String data, PublicKey pubkey, PrivateKey sigkey) throws Exception
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.SEND_MESSAGE);
		_segment.setSender(sender);
		_segment.setReceiver(receiver);
		
		// Encrypt data
		byte[] encrypted = Rsa.encrypt(pubkey, data.getBytes());
		String encrypteddata = Rsa.byteToString(encrypted);
		byte[] signed = Rsa.sign(sigkey, encrypted);
		String signeddata = Rsa.byteToString(signed);
		
		// Checksum
		String dchecksum = Function.checksum(encrypteddata).toString();
		String schecksum = Function.checksum(signeddata).toString();
		
		_segment.setData(encrypteddata);
		_segment.setDchecksum(dchecksum);
		_segment.setSignature(signeddata);
		_segment.setSchecksum(schecksum);
		
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
	}

	public static Segment newSegmentRequestSengMessage(String sender, String receiver, String length)
	{
		// New builder
		Segment.Builder _segment = Segment.newBuilder();
		// Set data for segment
		_segment.setType(Segment.SegmentType.REQUEST_SEND_MESSAGE);
		_segment.setSender(sender);
		_segment.setReceiver(receiver);
		_segment.setData("0");
		_segment.setDchecksum("0");
		_segment.setSignature("0");
		_segment.setSchecksum("0");
		_segment.setLength(length);
		// Build segment
		Segment segment = _segment.build();
		// Return segment
		return segment;
				
	}
	
	public static boolean isNext(Segment segment)
	{
		return segment.getType().equals(Segment.SegmentType.NEXT);
	}
	
	public static boolean isError(Segment segment)
	{
		return segment.getType().equals(Segment.SegmentType.ERROR);
	}
	
	public static boolean isAccept(Segment segment)
	{
		return segment.getType().equals(Segment.SegmentType.ACCEPT);
	}
	
	public static boolean isReject(Segment segment)
	{
		return segment.getType().equals(Segment.SegmentType.REJECT);
	}
	
	public static boolean isRequestConnect(Segment segment)
	{
		return segment.getType().equals(Segment.SegmentType.REQUEST_CONNECT);
	}
	
	public static boolean isDisconnect(Segment segment)
	{
		return segment.getType().equals(Segment.SegmentType.DISCONNECT);
	}
	
	public static boolean isRequestKey(Segment segment)
	{
		return segment.getType().equals(Segment.SegmentType.REQUEST_KEY);
	}
	
	public static boolean isSendKey(Segment segment)
	{
		return segment.getType().equals(Segment.SegmentType.SEND_KEY);
	}
	
	public static boolean isSendMessage(Segment segment)
	{
		return segment.getType().equals(Segment.SegmentType.SEND_MESSAGE);
	}
	
	public static boolean isRequestSendMessage(Segment segment)
	{
		return segment.getType().equals(Segment.SegmentType.REQUEST_SEND_MESSAGE);
	}
	
	
	
	public static void main(String[] args)
	{
		Segment c = newSegmentNext("conbocuoi", "hello");
		System.out.println(c.toString());
	}
}
