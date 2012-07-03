package otp;

import otp.helpr.BlockPlan;
import otp.response.OtpResponse;

public abstract class Otp
{
	
	/**
	 * Opens the OTP file or Stream or initializes the PRNG to be used. Loads all
	 * necessary information from the associated KeyRing object.
	 * 
	 * @throws OtpResponse
	 */
	public abstract void initialize() throws OtpResponse;
	
	/**
	 * Returns the next key byte from the current position. Needs to be
	 * initialized
	 * first.
	 * 
	 * @return The key byte
	 * @throws OtpResponse
	 */
	public abstract byte next() throws OtpResponse;
	
	/**
	 * Returns a number of key bytes from the current position and returns them as
	 * bytearray. Needs to be initialized first.
	 * 
	 * @param numBytes
	 * The number of bytes to be read
	 * @return The bytearray containing the key bytes
	 * @throws OtpResponse
	 */
	public byte[] next(int numBytes) throws OtpResponse
	{
		byte[] res = new byte[numBytes];
		for (int i = 0; i < numBytes; i++)
			res[i] = this.next();
		return res;
	}
	
	/**
	 * Fills a given bytearray with key bytes read from the current position.
	 * Needs to be initialized first.
	 * 
	 * @param b
	 * The bytearray to be filled
	 * @throws OtpResponse
	 */
	public void next(byte[] b) throws OtpResponse
	{
		for (int i = 0; i < b.length; i++)
			b[i] = this.next();
	}
	
	/**
	 * Overwrites the OTP at current position with a given
	 * bytearray.
	 * 
	 * @param b
	 * The bytearray the OTP should be overwritten with
	 * @throws OtpResponse
	 */
	public abstract void writeNext(byte[] b) throws OtpResponse;
	
	/**
	 * Returns the current OTP position. Needs to be initialized first. Needs to
	 * be initialized first.
	 * 
	 * @return The current position.
	 * @throws OtpResponse
	 */
	public abstract BlockPlan getPosition() throws OtpResponse;
	
	/**
	 * Moves the position pointer to a new location. Needs to be initialized
	 * first.
	 * 
	 * @param pos
	 * The new position the pointer should be set to
	 * @throws OtpResponse
	 */
	public abstract void setPosition(BlockPlan pos) throws OtpResponse;
	
	/**
	 * If initialized, reports the new position back to the associated KeySettings
	 * object. Closes all Input files.
	 * 
	 * @param success
	 * True, if the calling operation completed successfully
	 * @return The result of the operation
	 */
	public abstract OtpResponse finish(boolean success);
	
}
