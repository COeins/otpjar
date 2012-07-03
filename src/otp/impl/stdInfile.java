package otp.impl;

import java.io.IOException;
import java.io.InputStream;

import otp.Infile;
import otp.helpr.ByteArrayBuilder;
import otp.response.InfileResponse;

public class stdInfile extends Infile
{
	
	private byte[] bytes;
	private int counter;
	
	private boolean initialized = false;
	
	@Override
	public void initialize() throws InfileResponse
	{
		this.counter = 0;
		if (this.initialized)
			return;
		
		InputStream stdin = System.in;
		ByteArrayBuilder bab = new ByteArrayBuilder();
		
		try
		{
			boolean eof = false;
			while (!eof)
			{
				int in = stdin.read();
				if (in != -1)
					bab.add((byte) (in & 0xff));
				else
					eof = true;
			}
			
			this.bytes = bab.toArray();
		}
		catch (IOException e)
		{
			throw new InfileResponse(2, e);
		}
		
		this.initialized = true;
	}
	
	@Override
	public long getLength()
	{
		return this.bytes.length;
	}
	
	@Override
	public long getRemainingLength()
	{
		return this.bytes.length;
	}
	
	@Override
	public InfileResponse finish(boolean success)
	{
		return new InfileResponse(true);
		// return super.finish(success);
	}
	
	@Override
	public byte read() throws InfileResponse
	{
		if (this.counter >= this.bytes.length)
			throw new InfileResponse(2);
		else
			return this.bytes[this.counter++];
	}
	
}
