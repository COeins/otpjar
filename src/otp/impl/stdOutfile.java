package otp.impl;

import java.io.BufferedOutputStream;
import java.io.IOException;
import otp.Outfile;
import otp.response.OutfileResponse;

/**
 * Outfile module that writes all output to stdout
 */
public class stdOutfile extends Outfile
{
	
	private BufferedOutputStream out;
	private boolean initialized = false;
	
	@Override
	public void initialize() throws OutfileResponse
	{
		this.out = new BufferedOutputStream(System.out);
		this.initialized = true;
	}
	
	@Override
	public void write(byte b) throws OutfileResponse
	{
		if (this.initialized)
		{
			try
			{
				this.out.write(b);
			}
			catch (IOException e)
			{
				throw new OutfileResponse(2, e);
			}
		}
	}
	
	@Override
	public void write(byte[] b) throws OutfileResponse
	{
		if (this.initialized)
		{
			try
			{
				this.out.write(b);
			}
			catch (IOException e)
			{
				throw new OutfileResponse(2, e);
			}
		}
	}
	
	@Override
	public OutfileResponse finish(boolean success)
	{
		if (this.initialized)
		{
			try
			{
				this.out.flush();
				this.out.close();
			}
			catch (IOException e)
			{
				return new OutfileResponse(2, e);
			}
		}
		return new OutfileResponse(true);
	}
	
}
