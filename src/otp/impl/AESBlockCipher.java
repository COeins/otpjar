package otp.impl;

import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import otp.BlockCipher;
import otp.response.CipherResponse;

public class AESBlockCipher extends BlockCipher
{
	public static final int MODE_ECB = 0;
	public static final int MODE_CBC = 1;
	// public static final int MODE_CFB = 2;
	// public static final int MODE_OFB = 3;
	// public static final int MODE_CTR = 4;
	// public static final int MODE_CTS = 5;
	// those are not really needed now
	
	byte[] key;
	int direction = 0;
	int mode = 0;
	Cipher ciph = null;
	int blocksize = 0;
	
	@Override
	public void setKey(byte[] key) throws CipherResponse
	{
		if (key.length == 16)
			this.key = key;
		else
			throw new CipherResponse(2);
	}
	
	@Override
	public void setDirection(int direction)
	{
		this.direction = direction;
	}
	
	/**
	 * @throws CipherResponse
	 */
	public void setMode(int mode) throws CipherResponse
	{
		this.mode = mode;
	}
	
	@Override
	public void initialize() throws CipherResponse
	{
		String c;
		switch (this.mode)
		{
			case MODE_ECB:
				c = "ECB";
				break;
			case MODE_CBC:
				c = "CBC";
				break;
			default:
				throw new CipherResponse(4);
		}
		
		try
		{
			ciph = Cipher.getInstance("AES/" + c + "/NoPadding");
			SecretKeySpec sk = new SecretKeySpec(this.key, 0, 16, "AES");
			IvParameterSpec iv = new IvParameterSpec(new byte[16]);
			ciph.init(this.direction == BlockCipher.DIRECTION_DECRYPT ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, sk, iv);
			this.blocksize = ciph.getBlockSize();
		}
		catch (Exception e)
		{
			throw new CipherResponse(1, e);
		}
	}
	
	@Override
	public int getBlockSize()
	{
		return this.blocksize;
	}
	
	@Override
	public void next(byte[] input, byte[] output) throws CipherResponse
	{
		if (this.ciph == null)
			throw new CipherResponse(0);
		try
		{
			this.ciph.update(input, 0, input.length, output);
		}
		catch (ShortBufferException e)
		{
			throw new CipherResponse(1, e);
		}
	}
	
}
