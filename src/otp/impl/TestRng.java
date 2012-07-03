package otp.impl;

import java.util.Random;

import otp.Rng;
import otp.response.RngResponse;

public class TestRng extends Rng
{
	int cnt = 8;
	int length;
	Random rng;
	
	public TestRng(int length, long seed)
	{
		this.cnt = 8;
		this.length = length;
		this.rng = new Random(seed);
	}
	
	@Override
	public void initialize() throws RngResponse
	{
	}
	
	@Override
	public void reseed() throws RngResponse
	{
	}
	
	@Override
	public byte next() throws RngResponse
	{
		if (this.length <= 0)
		{
			byte[] b = new byte[1];
			rng.nextBytes(b);
			return b[0];
		}
		else
		{
			this.length--;
			if (this.cnt > 42)
				this.cnt = 4;
			return (byte) this.cnt++;
		}
	}
	
	@Override
	public RngResponse finish(boolean success)
	{
		return new RngResponse(true);
	}
	
}
