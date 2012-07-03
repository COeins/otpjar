package otp.impl;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import otp.Outfile;
import otp.UserInterface;
import otp.response.OutfileResponse;
import otp.response.UiResponse;

/**
 * Outfile Module that writes output to regular local file
 */
public class LocalOutfile extends Outfile
{
	private File file = null;
	private FileOutputStream foutput = null;
	private BufferedOutputStream boutput = null;
	private UserInterface ui = null;
	
	/**
	 * Creates new LocalOutfile
	 * 
	 * @param name
	 * The filename to be used. May include path. File will be
	 * overwritten
	 * @param ui
	 * The UserInterface for status messages
	 */
	public LocalOutfile(String name, UserInterface ui)
	{
		this.file = new File(name);
		this.ui = ui;
	}
	
	@Override
	public void initialize() throws OutfileResponse
	{
		if (this.file == null)
			throw new OutfileResponse(0);
		else
		{
			try
			{
				if (this.file.exists())
					if (!ui.promptYN("Overwrite file " + this.file.getName() + "?", false))
						throw new OutfileResponse(3);
				
				this.foutput = new FileOutputStream(this.file);
				this.boutput = new BufferedOutputStream(foutput);
			}
			catch (FileNotFoundException e)
			{
				throw new OutfileResponse(1);
			}
			catch (UiResponse r)
			{
				throw new OutfileResponse(0, r);
			}
		}
	}
	
	@Override
	public void write(byte b) throws OutfileResponse
	{
		try
		{
			this.boutput.write(b);
		}
		catch (IOException e)
		{
			throw new OutfileResponse(2);
		}
	}
	
	@Override
	public void write(byte b[]) throws OutfileResponse
	{
		try
		{
			this.boutput.write(b);
		}
		catch (IOException e)
		{
			throw new OutfileResponse(2);
		}
	}
	
	@Override
	public OutfileResponse finish(boolean success)
	{
		try
		{
			if (this.boutput != null)
			{
				this.boutput.close();
				if (!success)
				{
					if (this.file.exists() && this.file.canWrite())
						this.file.delete();
				}
			}
			
			return new OutfileResponse(true);
		}
		catch (IOException e)
		{
			return new OutfileResponse(2, e);
		}
	}
	
}
