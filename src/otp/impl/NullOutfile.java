package otp.impl;

import otp.Outfile;
import otp.response.OutfileResponse;

/**
 * Outfile Module that discards all output
 */
public class NullOutfile extends Outfile
{
	
	@Override
	public void initialize() throws OutfileResponse
	{
	}
	
	@Override
	public void write(byte b) throws OutfileResponse
	{
	}
	
	@Override
	public void write(byte[] b)
	{
	}
	
	@Override
	public OutfileResponse finish(boolean success)
	{
		return new OutfileResponse(true);
	}
	
}
