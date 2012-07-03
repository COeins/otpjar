package otp;

import otp.response.CipherResponse;

public abstract class BlockCipher
{
	public static final int DIRECTION_ENCRYPT = 0;
	public static final int DIRECTION_DECRYPT = 1;
	
	public abstract void setKey(byte[] key) throws CipherResponse;
	
	public abstract void setDirection(int direction) throws CipherResponse;
	
	public abstract void initialize() throws CipherResponse;
	
	public abstract int getBlockSize();
	
	public byte[] next(byte[] input) throws CipherResponse
	{
		int bs = this.getBlockSize();
		byte[] res = new byte[(input.length / bs) * bs];
		this.next(input, res);
		return res;
	}
	
	public abstract void next(byte[] input, byte[] output) throws CipherResponse;
	
}
