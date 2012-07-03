package otp.impl;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import otp.Rng;
import otp.UserInterface;
import otp.response.RngResponse;

/**
 * Rng module that uses a PRNG for creating random bytes
 */
public class PseudoRNG extends Rng
{
	SecureRandom rng;
	private UserInterface ui;
	private boolean firstbyte = true;
	
	/**
	 * Creates new Pseudo RNG
	 * 
	 * @param ui
	 * UserInterface for status messages
	 */
	public PseudoRNG(UserInterface ui)
	{
		this.ui = ui;
	}
	
	@Override
	public void initialize() throws RngResponse
	{
		try
		{
			this.rng = SecureRandom.getInstance("SHA1PRNG");
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new RngResponse(0, e);
		}
		
	}
	
	@Override
	public void reseed() throws RngResponse
	{
		this.initialize();
	}
	
	@Override
	public byte next() throws RngResponse
	{
		if (this.rng == null)
			throw new RngResponse(0);
		
		byte[] b = new byte[1];
		this.rng.nextBytes(b);
		return b[0];
	}
	
	@Override
	public byte[] next(int numBytes) throws RngResponse
	{
		if (this.rng == null)
			throw new RngResponse(0);
		
		if (this.firstbyte)
			this.ui.message("Collecting randomness...");
		this.firstbyte = false;
		
		byte[] b = new byte[numBytes];
		this.rng.nextBytes(b);
		return b;
	}
	
	@Override
	public RngResponse finish(boolean success)
	{
		return new RngResponse(true);
	}
	
	@Override
	public int nextInt(int i) throws RngResponse
	{
		if (this.rng == null)
			throw new RngResponse(0);
		
		if (this.firstbyte)
			this.ui.message("Collecting randomness...");
		this.firstbyte = false;
		
		return this.rng.nextInt(i);
	}
	
	@Override
	public double nextDouble() throws RngResponse
	{
		if (this.rng == null)
			throw new RngResponse(0);
		
		if (this.firstbyte)
			this.ui.message("Collecting randomness...");
		this.firstbyte = false;
		
		return this.rng.nextDouble();
	}
	
}
