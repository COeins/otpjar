package otp.impl;

import otp.Infile;
import otp.response.InfileResponse;

public class BaInfile extends Infile
{
	
	byte[] content;
	int counter = 0;
	
	public BaInfile(byte[] content)
	{
		this.content = content;
	}
	
	public void useBytesFrom(byte[] source)
	{
		this.content = source;
	}
	
	@Override
	public void initialize() throws InfileResponse
	{
		this.counter = 0;
	}
	
	@Override
	public byte read() throws InfileResponse
	{
		return this.content[this.counter++];
	}
	
	@Override
	public long getLength()
	{
		return this.content.length;
	}
	
	@Override
	public long getRemainingLength()
	{
		return this.content.length - this.counter;
	}
	
	@Override
	public InfileResponse finish(boolean success)
	{
		return new InfileResponse(true);
		// return super.finish(success);
	}
	
}
