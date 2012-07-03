package otp;

import otp.helpr.ByteArray;
import otp.response.RngResponse;

public abstract class Rng
{
	
	/**
	 * Initializes the used PRNG or opens the random number stream.
	 * 
	 * @throws RngResponse
	 */
	public abstract void initialize() throws RngResponse;
	
	/**
	 * In case of a PRNG generates a new seed value. Needs to be initialized
	 * first.
	 * 
	 * @throws RngResponse
	 */
	public abstract void reseed() throws RngResponse;
	
	/**
	 * Returns the next random byte. Needs to be initialized first.
	 * 
	 * @return The random byte
	 * @throws RngResponse
	 */
	public abstract byte next() throws RngResponse;
	
	/**
	 * Returns an array of random bytes. Needs to be initialized first.
	 * 
	 * @param numBytes
	 * The number of bytes to be returned
	 * @return The array filled with random bytes
	 * @throws RngResponse
	 */
	public byte[] next(int numBytes) throws RngResponse
	{
		byte[] b = new byte[numBytes];
		for (int i = 0; i < numBytes; i++)
			b[i] = this.next();
		
		return b;
	}
	
	/**
	 * Fills an array with random bytes. Needs to be initialized first.
	 * 
	 * @param b
	 * The array to be filled with random bytes
	 * @throws RngResponse
	 */
	public void next(byte[] b) throws RngResponse
	{
		for (int i = 0; i < b.length; i++)
			b[i] = this.next();
	}
	
	/**
	 * Returns a random positive Integer distributed uniformly between 0
	 * (inclusive) and a given upper bound (exclusive). Needs to be initialized
	 * first.
	 * 
	 * @param i
	 * The upper bound. Needs to be a positive integer
	 * @return The random number
	 * @throws RngResponse
	 */
	public int nextInt(int i) throws RngResponse
	{
		if (i <= 0)
			throw new RngResponse(0);
		
		byte[] b = new byte[4];
		int rand, res;
		
		do
		{
			this.next(b);
			b[0] &= 127;
			rand = ByteArray.toInt(b);
			res = rand % i;
		}
		while (rand - res + (i - 1) < 0);
		return res;
	}
	
	/**
	 * Returns an uniformly distributed random number between [0, 1[
	 * 
	 * @return
	 * @throws RngResponse
	 */
	public double nextDouble() throws RngResponse
	{
		byte[] r = new byte[8];
		System.arraycopy(this.next(7), 0, r, 1, 7);
		return (double) (ByteArray.toLong(r) & 0x001FFFFFFFFFFFFFL) / 9007199254740992D;
	}
	
	/**
	 * In initialized, closes all used resources.
	 * 
	 * @param success
	 * True, if the calling operation completed successfully
	 * @return The result of the operation
	 */
	public abstract RngResponse finish(boolean success);
}
