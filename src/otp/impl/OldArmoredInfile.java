package otp.impl;

import java.io.IOException;
import java.io.InputStream;
import java.util.NoSuchElementException;
import java.util.Scanner;

import otp.Infile;
import otp.helpr.ByteArray;
import otp.response.InfileResponse;

/**
 * Infile module that reads and decodes a Radix64 encoded local file
 */
public class OldArmoredInfile extends Infile
{
	
	Infile outerInput = null;
	private byte[] bytes;
	private int counter;
	private boolean initialized = false;
	private BaInfile bain = null;
	
	/**
	 * Creates new ArmoredInfile
	 * 
	 * @param name
	 * The Filename, may include path
	 */
	public OldArmoredInfile(Infile read)
	{
		this.outerInput = read;
	}
	
	public OldArmoredInfile(Infile read, BaInfile ba)
	{
		this.outerInput = read;
		this.bain = ba;
	}
	
	@Override
	public void initialize() throws InfileResponse
	{
		if (this.outerInput == null)
			throw new InfileResponse(0);
		else
		{
			this.counter = 0;
			if (this.initialized)
				return;
			
			this.outerInput.initialize();
			final long inputlength = outerInput.getLength();
			
			// create a Scanner from any Infile class
			Scanner s = new Scanner(new InputStream()
			{
				long size = inputlength;
				long read = 0;
				
				@Override
				public int read() throws IOException
				{
					if (read < size)
					{
						try
						{
							int ret = (int) outerInput.read() & 0xFF;
							read++;
							return ret;
						}
						catch (InfileResponse r)
						{
							if (r.getErrorCode() == 2 && r.getCause() instanceof IOException)
								throw (IOException) r.getCause();
							else
								throw new IOException();
						}
					}
					else
						return -1;
				}
			});
			
			StringBuilder sb = new StringBuilder();
			
			boolean started = false;
			boolean ended = false;
			
			while (s.hasNextLine() && !ended)
			{
				String sx = s.nextLine().trim();
				while (sx.length() > 0 && sx.charAt(0) == '>')
					sx = sx.substring(1).trim();
				
				if (started)
				{
					if (sx.trim().equals("-----END OTP MESSAGE-----"))
						ended = true;
					else if (!sx.equals(""))
						sb.append(sx);
				}
				else if (sx.trim().equals("-----BEGIN OTP MESSAGE-----"))
					started = true;
			}
			
			if (this.bain != null)
			{
				StringBuilder sb1 = new StringBuilder();
				try
				{
					while (true)
					{
						sb1.append(s.nextLine());
						sb1.append("\n");
					}
				}
				catch (NoSuchElementException e)
				{
				}
				
				this.bain.useBytesFrom(sb1.toString().getBytes());
			}
			
			s.close();
			this.outerInput.finish(true);
			int len = sb.length();
			if (len < 5)
				throw new InfileResponse(3);
			
			String data = sb.substring(0, len - 5);
			this.bytes = ByteArray.fromRadix64(data);
			
			int crc1 = ByteArray.toInt(ByteArray.fromRadix64(sb.substring(len - 4, len)));
			int crc2 = ByteArray.crc24(bytes, 0xb704ce);
			
			if (crc1 != crc2)
				throw new InfileResponse(2);
			
			this.initialized = true;
		}
		
	}
	
	@Override
	public byte read() throws InfileResponse
	{
		try
		{
			return this.bytes[this.counter++];
		}
		catch (ArrayIndexOutOfBoundsException e)
		{
			throw new InfileResponse(2, e);
		}
	}
	
	@Override
	public byte[] read(int bytes) throws InfileResponse
	{
		byte[] out = new byte[bytes];
		this.read(out);
		return out;
	}
	
	@Override
	public void read(byte[] b) throws InfileResponse
	{
		try
		{
			System.arraycopy(this.bytes, this.counter, b, 0, b.length);
			this.counter += b.length;
		}
		catch (ArrayIndexOutOfBoundsException e)
		{
			throw new InfileResponse(2, e);
		}
	}
	
	@Override
	public long getLength()
	{
		return this.bytes.length;
	}
	
	@Override
	public long getRemainingLength()
	{
		return this.bytes.length - this.counter;
	}
	
	@Override
	public InfileResponse finish(boolean success)
	{
		return new InfileResponse(true);
		// return super.finish(success);
	}
}
