package otp.impl;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import otp.Infile;
import otp.response.InfileResponse;

/**
 * Infile module that reads input from regular local file
 */
public class LocalInfile extends Infile
{
	
	File file = null;
	String filename = null;
	FileInputStream finput = null;
	BufferedInputStream binput = null;
	
	long filelength = 0;
	long read = 0;
	
	/**
	 * Creates new LocalInfile
	 * 
	 * @param name
	 * Filename, may include path.
	 * @return
	 */
	public LocalInfile(String name)
	{
		this.filename = name;
	}
	
	@Override
	public void initialize() throws InfileResponse
	{
		if (this.filename == null)
			throw new InfileResponse(0);
		else
		{
			try
			{
				this.file = new File(this.filename);
				this.finput = new FileInputStream(this.file);
				this.binput = new BufferedInputStream(this.finput);
				this.filelength = this.binput.available();
			}
			catch (FileNotFoundException e)
			{
				throw new InfileResponse(1, e);
			}
			catch (IOException e)
			{
				throw new InfileResponse(2, e);
			}
		}
		
	}
	
	@Override
	public byte read() throws InfileResponse
	{
		try
		{
			Byte a = (byte) this.binput.read();
			this.read++;
			return a;
		}
		catch (IOException e)
		{
			throw new InfileResponse(2, e);
		}
	}
	
	@Override
	public void read(byte[] b) throws InfileResponse
	{
		try
		{
			this.binput.read(b);
			this.read += b.length;
		}
		catch (IOException e)
		{
			throw new InfileResponse(2, e);
		}
	}
	
	@Override
	public long getLength()
	{
		return this.filelength;
	}
	
	@Override
	public long getRemainingLength() throws InfileResponse
	{
		try
		{
			return this.binput.available();
		}
		catch (IOException e)
		{
			throw new InfileResponse(2, e);
		}
	}
	
	@Override
	public InfileResponse finish(boolean success)
	{
		InfileResponse s = new InfileResponse(true);
		// s = super.finish(success);
		
		try
		{
			if (this.binput != null)
				this.binput.close();
			return s;
		}
		catch (IOException e)
		{
			return new InfileResponse(2, e);
		}
	}
	
}
