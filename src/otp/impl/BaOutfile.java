package otp.impl;

import otp.Outfile;
import otp.helpr.ByteArrayBuilder;
import otp.response.OutfileResponse;

public class BaOutfile extends Outfile
{
	
	ByteArrayBuilder bab;
	
	@Override
	public void initialize() throws OutfileResponse
	{
		this.bab = new ByteArrayBuilder();
	}
	
	@Override
	public void write(byte b) throws OutfileResponse
	{
		this.bab.add(b);
	}
	
	@Override
	public OutfileResponse finish(boolean success)
	{
		return null;
	}
	
	public byte[] getContent()
	{
		return this.bab.toArray();
	}
}
