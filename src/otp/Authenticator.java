package otp;

import otp.response.AuthResponse;

public abstract class Authenticator
{
	/**
	 * Defines the length of the authenticated data. Has to be called before
	 * initialize().
	 * 
	 * @param filelength
	 * The input length in byte
	 * @return
	 * Number of OTP bytes used for specified input
	 * @throws AuthResponse
	 */
	public abstract int setInputSize(long filelength) throws AuthResponse;
	
	/**
	 * Initializes the authentication process. May require the input length to be
	 * defined via setInputsize().
	 * 
	 * @throws AuthResponse
	 */
	public abstract void initialize() throws AuthResponse;
	
	/**
	 * Takes one byte for authentication. Requires initialize() to be called
	 * first.
	 * 
	 * @param e
	 * The byte to be authenticated
	 * @throws AuthResponse
	 */
	public abstract void next(byte e) throws AuthResponse;
	
	/**
	 * Takes an array of bytes for authentication. Requires initialize() to be
	 * called first.
	 * 
	 * @param b
	 * The bytes to be authenticated
	 * @throws AuthResponse
	 */
	public void next(byte[] b) throws AuthResponse
	{
		for (byte b1 : b)
		{
			this.next(b1);
		}
	}
	
	/**
	 * Completes the authentication process and returns the generated MAC.
	 * Requires initialize() to be called first.
	 * 
	 * @return The generated Authentication Code
	 * @throws AuthResponse
	 */
	public abstract byte[] doFinal() throws AuthResponse;
	
	/**
	 * Return the length of a MAC generated with this class Requires initialize()
	 * to be called first.
	 * 
	 * @return The length of the MAC in byte
	 * @throws AuthResponse
	 */
	public abstract int getMacLength() throws AuthResponse;
	
	/**
	 * If initialized, used keys are closed. May be initialized and used again.
	 * 
	 * @param success
	 * True, if the calling operation completed successfully
	 * @return The result of the operation
	 */
	public abstract AuthResponse finish(boolean success);
	
}
