package otp;

import otp.response.InfileResponse;

public abstract class Infile
{
	
	/**
	 * Initializes the input stream.
	 * 
	 * @throws InfileResponse
	 */
	public abstract void initialize() throws InfileResponse;
	
	/**
	 * Reads one byte from the input stream. Needs to be initialized first.
	 * 
	 * @return The read byte
	 * @throws InfileResponse
	 */
	public abstract byte read() throws InfileResponse;
	
	/**
	 * Reads a number of bytes from the input stream and returns them as an array.
	 * Needs to be initialized first.
	 * 
	 * @param numBytes
	 * Number of bytes to be read.
	 * @return The read bytes
	 * @throws InfileResponse
	 */
	public byte[] read(int numBytes) throws InfileResponse
	{
		byte[] res = new byte[numBytes];
		for (int i = 0; i < numBytes; i++)
			res[i] = this.read();
		return res;
	}
	
	/**
	 * Fills a given array with bytes read from the input stream. Needs to be
	 * initialized first.
	 * 
	 * @param b
	 * The bytearray to be filled.
	 * @throws InfileResponse
	 */
	public void read(byte[] b) throws InfileResponse
	{
		for (int i = 0; i < b.length; i++)
			b[i] = this.read();
	}
	
	/**
	 * Returns the length of the input file. Needs to be initialized first.
	 * 
	 * @return Length of input stream.
	 */
	public abstract long getLength() throws InfileResponse;;
	
	/**
	 * Returns the remaining length of the input file. Needs to be initialized
	 * first.
	 * 
	 * @return Remaining length of input stream.
	 * @throws InfileResponse
	 */
	public abstract long getRemainingLength() throws InfileResponse;
	
	/**
	 * If initialized, the input file is closed.
	 * 
	 * @param success
	 * True, if the calling operation completed successfully.
	 * @return The result of the operation
	 */
	public abstract InfileResponse finish(boolean success);
	
}
