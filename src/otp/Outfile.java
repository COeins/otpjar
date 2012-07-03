package otp;

import otp.response.OutfileResponse;

public abstract class Outfile
{
	
	/**
	 * Initializes the output stream.
	 * 
	 * @throws OutfileResponse
	 */
	public abstract void initialize() throws OutfileResponse;
	
	/**
	 * Writes a byte to the output stream. Needs to be initialized first.
	 * 
	 * @param b
	 * The byte to be written.
	 * @throws OutfileResponse
	 */
	public abstract void write(byte b) throws OutfileResponse;
	
	/**
	 * Writes a number of bytes to the output stream. Needs to be initialized
	 * first.
	 * 
	 * @param b
	 * The bytearray to be written.
	 * @throws OutfileResponse
	 */
	public void write(byte[] b) throws OutfileResponse
	{
		for (byte b1 : b)
		{
			this.write(b1);
		}
	}
	
	/**
	 * If initialized, writes all cached bytes and closes output stream.
	 * 
	 * @param success
	 * True, if the calling operation completed successfully
	 * @return The result of the operation
	 */
	public abstract OutfileResponse finish(boolean success);
	
}
