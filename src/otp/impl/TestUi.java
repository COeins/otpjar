package otp.impl;

import otp.UserInterface;

public class TestUi extends UserInterface
{
	
	boolean normal;
	boolean verbose;
	boolean error;
	StringBuilder messages = null;
	
	public TestUi(boolean normal, boolean verbose, boolean error)
	{
		this.normal = normal;
		this.verbose = verbose;
		this.error = error;
		this.messages = new StringBuilder();
	}
	
	@Override
	public void initializeProgress(long max)
	{
		
	}
	
	@Override
	public void updateProgress(long current)
	{
		
	}
	
	@Override
	public void finishProgress()
	{
		
	}
	
	@Override
	public byte[] getPassphrase(String keyId)
	{
		return new byte[] { 4, 8, 15, 16, 23, 42 };
	}
	
	@Override
	public byte[] getNewPassphrase(String keyId)
	{
		return new byte[] { 4, 8, 15, 16, 23, 42 };
	}
	
	@Override
	public Boolean promptYN(String prompt, Boolean def)
	{
		return true;
	}
	
	@Override
	public Long promptNumber(String prompt, Long def, Long min, Long max)
	{
		return 1L;
	}
	
	@Override
	public String promptStr(String prompt, String def)
	{
		return "abcdefg";
	}
	
	@Override
	public void message(String message)
	{
		if (this.normal)
			System.out.println(message);
		else
		{
			this.messages.append(message);
			this.messages.append("\n");
		}
	}
	
	@Override
	public void verboseMessage(String message)
	{
		if (this.verbose)
			System.out.println(message);
		else
		{
			this.messages.append("V: ");
			this.messages.append(message);
			this.messages.append("\n");
		}
	}
	
	@Override
	public void warningMessage(String message)
	{
		if (this.error)
			System.err.println(message);
		else
		{
			this.messages.append("E: ");
			this.messages.append(message);
			this.messages.append("\n");
		}
	}
	
	public void printCache()
	{
		System.out.print(this.messages.toString());
	}
	
	public void clearCache()
	{
		this.messages = new StringBuilder();
	}
}
