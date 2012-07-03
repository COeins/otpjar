package otp.impl;

import otp.Infile;
import otp.response.InfileResponse;

public class TestInfile extends Infile
{
	int length;
	int ctr = 0;
	int start;
	int input;
	
	public TestInfile(int length, int start)
	{
		this.length = length;
		this.start = start;
	}
	
	@Override
	public void initialize() throws InfileResponse
	{
		this.input = this.start;
		this.ctr = 0;
	}
	
	@Override
	public byte read() throws InfileResponse
	{
		if (this.ctr >= this.length)
			throw new InfileResponse(2);
		if (this.input > 120)
			this.input = this.start;
		this.ctr++;
		return (byte) this.input++;
	}
	
	@Override
	public long getLength()
	{
		return this.length;
	}
	
	@Override
	public long getRemainingLength()
	{
		return this.length - this.ctr;
	}
	
	@Override
	public InfileResponse finish(boolean success)
	{
		return new InfileResponse(true);
		// return super.finish(success);
	}
}
