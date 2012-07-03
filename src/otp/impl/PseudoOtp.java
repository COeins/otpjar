package otp.impl;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import otp.Otp;
import otp.helpr.BlockPlan;
import otp.response.KeyringResponse;
import otp.response.OtpResponse;

/**
 * Otp module that uses PRNG as Source. This module is just for testing purposes
 * and should not be used in a real application.
 */
// TODO rework class
public class PseudoOtp extends Otp
{
	
	SecureRandom rng = null;
	byte[] seed = null;
	int position = 0;
	PseudoKey set = null;
	int count = 0;
	
	/**
	 * Creates now PseudoOtp
	 * 
	 * @param set
	 * The corresponding PseudoKey module
	 */
	public PseudoOtp(PseudoKey set)
	{
		this.set = set;
	}
	
	@Override
	public void initialize() throws OtpResponse
	{
		
		try
		{
			this.seed = this.set.getseed();
			this.rng = SecureRandom.getInstance("SHA1PRNG");
			this.rng.setSeed(this.seed);
			// this.setPosition(this.set.get_position());
		}
		catch (KeyringResponse e)
		{
			throw new OtpResponse(0, e);
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new OtpResponse(0, e);
		}
		
	}
	
	@Override
	public byte next() throws OtpResponse
	{
		if (this.rng == null)
			throw new OtpResponse(0);
		byte[] rnd = new byte[1];
		this.position++;
		this.rng.nextBytes(rnd);
		
		return rnd[0];
	}
	
	@Override
	public BlockPlan getPosition()
	{
		// return this.position;
		return null;
	}
	
	@Override
	public void setPosition(BlockPlan bp) throws OtpResponse
	{
		int pos = bp.getPointer();
		
		if (pos < 0)
			throw new OtpResponse(0);
		
		if (pos < this.position)
		{
			try
			{
				this.rng = SecureRandom.getInstance("SHA1PRNG");
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new OtpResponse(0);
			}
			
			this.rng.setSeed(this.seed);
			this.position = 0;
		}
		
		if (pos > this.position)
		{
			byte[] trash = new byte[(int) pos - this.position];
			this.rng.nextBytes(trash);
			this.position = (int) pos;
			trash = null;
		}
		
	}
	
	@Override
	public OtpResponse finish(boolean success)
	{
		try
		{
			this.set.set_position(this.position);
		}
		catch (KeyringResponse e)
		{
			return new OtpResponse(0);
		}
		return new OtpResponse(true);
	}
	
	/**
	 * Not supported!
	 */
	@Override
	public void writeNext(byte[] b) throws OtpResponse
	{
		throw new OtpResponse(0);
	}
}
