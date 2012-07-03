package otp.impl;

import otp.Outfile;
import otp.response.OutfileResponse;

public class TestOutfile extends Outfile
{
	int length;
	int ctr = 0;
	int start;
	int input;
	
	public TestOutfile(int length, int start)
	{
		this.length = length;
		this.start = start;
	}
	
	@Override
	public void initialize() throws OutfileResponse
	{
		this.input = this.start;
		this.ctr = 0;
	}
	
	@Override
	public void write(byte b) throws OutfileResponse
	{
		if (this.input > 120)
			this.input = this.start;
		
		if (this.ctr >= this.length)
		{
			System.err.println("Output to long:" + this.ctr + " of " + this.length);
			throw new OutfileResponse(0);
		}
		if (this.input != (int) b)
		{
			System.err.println("Unexpected output: " + this.input + " != " + (int) b);
			throw new OutfileResponse(0);
		}
		ctr++;
		this.input++;
	}
	
	@Override
	public OutfileResponse finish(boolean success)
	{
		if (this.ctr < this.length && success)
		{
			System.err.println("Output to short: " + this.ctr + " of " + this.length);
			return new OutfileResponse(0);
		}
		
		return null;
	}
	
}
