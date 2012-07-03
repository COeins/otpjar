package otp.impl;

import otp.Infile;
import otp.helpr.ByteArray;
import otp.helpr.ByteArrayBuilder;
import otp.response.InfileResponse;

/**
 * Infile module that reads and decodes a Radix64 encoded local file
 */
public class ArmoredInfile extends Infile
{
	
	Infile outerInput = null;
	private byte[] bytes;
	private int counter;
	private boolean initialized = false;
	private BaInfile bain = null;
	//private boolean reuse = false;
	
	/**
	 * Creates new ArmoredInfile
	 * 
	 * @param name
	 * The Filename, may include path
	 */
	public ArmoredInfile(Infile read)
	{
		this.outerInput = read;
	}
	
	public ArmoredInfile(Infile read, BaInfile reuseInput)
	{
		this.outerInput = read;
		this.bain = reuseInput;
	}
	
	@Override
	public void initialize() throws InfileResponse
	{
		if (this.outerInput == null)
			throw new InfileResponse(0);
		
		this.counter = 0;
		if (this.initialized)
			return;
		
		this.outerInput.initialize();
		final long inputLength = outerInput.getLength();
		
		StringBuilder lines = new StringBuilder();
		ByteArrayBuilder lineB;
		String line;
		
		long read = 0;
		
		boolean started = false;
		boolean ended = false;
		
		while (read < inputLength && !ended)
		{
			lineB = new ByteArrayBuilder();
			while (read < inputLength)
			{
				byte b = outerInput.read();
				read++;
				if (b == 10 || b == 13)
				{
					if (lineB.size() > 0)
						break;
				}
				else
					lineB.add(b);
			}
			
			line = lineB.toString().trim();
			while (line.length() > 0 && line.charAt(0) == '>')
				line = line.substring(1).trim();
			
			if (started)
			{
				if (line.trim().equals("-----END OTP MESSAGE-----"))
					ended = true;
				else if (!line.equals(""))
					lines.append(line);
			}
			else if (line.trim().equals("-----BEGIN OTP MESSAGE-----"))
				started = true;
		}
		
		if (this.bain != null)
		{
			if (inputLength - read > Integer.MAX_VALUE)
				throw new InfileResponse(0);
			
			byte[] remaining = new byte[(int) (inputLength - read)];
			this.outerInput.read(remaining);
			this.bain.useBytesFrom(remaining);
		}
			
		this.outerInput.finish(true);
		
		int len = lines.length();
		if (len < 5)
			throw new InfileResponse(3);
		
		String data = lines.substring(0, len - 5);
		this.bytes = ByteArray.fromRadix64(data);
		
		int crc1 = ByteArray.toInt(ByteArray.fromRadix64(lines.substring(len - 4, len)));
		int crc2 = ByteArray.crc24(bytes, 0xb704ce);
		
		if (crc1 != crc2)
			throw new InfileResponse(2);
		
		this.initialized = true;
		
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
	}
}
