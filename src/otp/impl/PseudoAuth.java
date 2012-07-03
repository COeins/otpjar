package otp.impl;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import otp.Authenticator;
import otp.Otp;
import otp.response.AuthResponse;
import otp.response.OtpResponse;

/**
 * Authenticator module that uses Hmac/MD5 authentication This module is just
 * for testing purposes and should not be used in a real application.
 */
public class PseudoAuth extends Authenticator
{
	Otp otp = null;
	Mac mac = null;
	
	/**
	 * Creates new PseudoAuth
	 * 
	 * @param otp
	 * The Otp odule to be used, set to the authentication position
	 */
	public PseudoAuth(Otp otp)
	{
		this.otp = otp;
	}
	
	@Override
	public void initialize() throws AuthResponse
	{
		if (this.otp == null)
			throw new AuthResponse(0);
		
		try
		{
			this.mac = Mac.getInstance("HmacMD5");
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new AuthResponse(0, e);
		}
		
		byte[] rawkey = new byte[16];
		
		for (int i = 0; i < rawkey.length; i++)
		{
			try
			{
				rawkey[i] = this.otp.next();
			}
			catch (OtpResponse e)
			{
				throw new AuthResponse(1, e);
			}
		}
		Key k = new SecretKeySpec(rawkey, "HmacMD5");
		
		try
		{
			this.mac.init(k);
		}
		catch (InvalidKeyException e)
		{
			throw new AuthResponse(0, e);
		}
	}
	
	@Override
	public void next(byte e)
	{
		this.mac.update(e);
	}
	
	@Override
	public byte[] doFinal()
	{
		return this.mac.doFinal();
	}
	
	@Override
	public int getMacLength()
	{
		return 16;
	}
	
	@Override
	public AuthResponse finish(boolean success)
	{
		return new AuthResponse(true);
	}
	
	@Override
	public int setInputSize(long filelength)
	{
		return 0;
	}
	
}
