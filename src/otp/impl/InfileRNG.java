package otp.impl;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

import otp.Rng;
import otp.UserInterface;
import otp.response.RngResponse;

public class InfileRNG extends Rng
{
	
	boolean initialized = false;
	File filename = null;
	FileInputStream finput = null;
	BufferedInputStream binput = null;
	Rng rng = null;
	UserInterface ui = null;
	
	long filelength = 0;
	long read = 0;
	
	/**
	 * Creates new InfileRNG
	 * 
	 * @param filename
	 * The file the randomness should be read from. May inclde path
	 * @param rng
	 * The RNG module to be used if all bytes of the input file are
	 * returned
	 * @param ui
	 * The UserInterface for status messages
	 */
	public InfileRNG(String filename, Rng rng, UserInterface ui)
	{
		this.filename = new File(filename);
		this.rng = rng;
		this.ui = ui;
	}
	
	@Override
	public void initialize() throws RngResponse
	{
		if (this.initialized)
			return;
		
		if (this.filename == null)
			throw new RngResponse(0);
		else
		{
			try
			{
				this.finput = new FileInputStream(this.filename);
				this.binput = new BufferedInputStream(this.finput);
				this.filelength = this.binput.available();
				this.ui.verboseMessage("Random number file " + filename + " opened, " + this.filelength + " bytes available.");
				this.rng.initialize();
			}
			catch (FileNotFoundException e)
			{
				throw new RngResponse(1, e);
			}
			catch (IOException e)
			{
				throw new RngResponse(1, e);
			}
		}
		
		this.initialized = true;
		
	}
	
	@Override
	public void reseed() throws RngResponse
	{
		this.rng.reseed();
	}
	
	@Override
	public byte next() throws RngResponse
	{
		if (!this.initialized)
			throw new RngResponse(0);
		
		if (this.read < this.filelength)
			try
			{
				Byte a = (byte) this.binput.read();
				this.read++;
				return a;
			}
			catch (IOException e)
			{
				throw new RngResponse(1, e);
			}
		else
			return this.rng.next();
	}
	
	@Override
	public void next(byte[] b) throws RngResponse
	{
		if (!this.initialized)
			throw new RngResponse(0);
		
		if (this.read + b.length < this.filelength)
			try
			{
				this.binput.read(b);
			}
			catch (IOException e)
			{
				throw new RngResponse(1, e);
			}
		else
			super.next(b);
	}
	
	@Override
	public RngResponse finish(boolean success)
	{
		if (!this.initialized)
			return new RngResponse(true);
		
		try
		{
			if (this.binput != null)
				this.binput.close();
			RngResponse r = this.rng.finish(success);
			
			if (r.getSuccess())
				return new RngResponse(true);
			else
				return r;
		}
		catch (IOException e)
		{
			return new RngResponse(2, e);
		}
	}
	
}
