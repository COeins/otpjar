package otp.impl;

import otp.Outfile;
import otp.helpr.ByteArray;
import otp.helpr.ByteArrayBuilder;
import otp.response.OutfileResponse;

/**
 * Outfile module that creates a Radix64 encoded local file
 */
public class ArmoredOutfile extends Outfile
{
	Outfile out;
	ByteArrayBuilder bab;
	
	/**
	 * Creates new ArmoredOutfile
	 * 
	 * @param out
	 * Filename, may include path. Existing file will be overwritten
	 */
	public ArmoredOutfile(Outfile out)
	{
		this.out = out;
	}
	
	@Override
	public void initialize() throws OutfileResponse
	{
		this.out.initialize();
		this.bab = new ByteArrayBuilder();
	}
	
	@Override
	public void write(byte b) throws OutfileResponse
	{
		this.bab.add(b);
	}
	
	@Override
	public OutfileResponse finish(boolean success)
	{
		try
		{
			if (success)
			{
				if (this.out == null)
					return new OutfileResponse(0);
				else
				{
					out.write("-----BEGIN OTP MESSAGE-----\r\n".getBytes());
					out.write("\r\n".getBytes());
					out.write((ByteArray.toRadix64(this.bab.toArray()) + "\r\n").getBytes());
					
					byte[] crc0 = ByteArray.fromInt(ByteArray.crc24(bab.toArray(), 0xb704ce));
					byte[] crc1 = new byte[] { crc0[1], crc0[2], crc0[3] };
					String crc = "=" + ByteArray.toRadix64(crc1) + "\r\n";
					out.write(crc.getBytes());
					out.write("-----END OTP MESSAGE-----\r\n".getBytes());
					this.bab.clear();
					this.out.finish(success);
				}
				return new OutfileResponse(true);
			}
			else
			{
				this.out.finish(success);
				return new OutfileResponse(true);
			}
		}
		catch (OutfileResponse e)
		{
			return e;
		}
		
	}
	
}
