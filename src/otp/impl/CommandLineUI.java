package otp.impl;

import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;

import otp.UserInterface;
import otp.response.UiResponse;

/**
 * UserInterface module that uses stdin, stdout and stderr
 */
public class CommandLineUI extends UserInterface
{
	
	private InputStreamReader stdin = new InputStreamReader(System.in);
	private Console con = System.console();
	
	private long max = 100;
	private long step = 1;
	private int last = -1;
	
	private boolean quiet = false;
	private boolean verbose = false;
	private boolean assumeyes = false;
	private boolean assumeno = false;
	private boolean disableInteractivity = false;
	private long before;
	
	private String ringId;
	private byte[] passphrase;
	private byte[][] prePassphrase;
	private int preselectedPwd = 0;
	private int prePwdRead = 0;
	
	/**
	 * Creates new CommandLineUI
	 */
	public CommandLineUI()
	{
	}
	
	/**
	 * Creates new CommandLineUI and initializes some values
	 * 
	 * @param quiet
	 * If true, discards less important status messages
	 * @param verbose
	 * If true, outputs verbose status messages
	 * @param yes
	 * If true, returns true on Yes/NO questions
	 * @param no
	 * If true, returns false on Yes/NO questions
	 */
	public CommandLineUI(boolean quiet, boolean verbose, boolean yes, boolean no)
	{
		this.quiet = quiet;
		this.verbose = verbose;
		this.assumeyes = yes;
		this.assumeno = no;
	}
	
	/**
	 * Discards all following less important status messages
	 */
	public void setQuiet()
	{
		this.quiet = true;
		this.verbose = false;
	}
	
	/**
	 * Displays all following verbose status messages
	 */
	public void setVerbose()
	{
		this.quiet = false;
		this.verbose = true;
		System.out.println("Verbose logging enabled.");
	}
	
	/**
	 * Answers all following Yes/No questions with true
	 */
	public void setYes()
	{
		this.assumeyes = true;
		this.assumeno = false;
	}
	
	/**
	 * Answers all following Yes/No questions with false
	 */
	public void setNo()
	{
		this.assumeyes = false;
		this.assumeno = true;
	}
	
	/**
	 * Disable following Yes/No questions and password prompts
	 */
	public void disableInteractivity()
	{
		this.disableInteractivity = true;
	}
	
	@Override
	public void initializeProgress(long max)
	{
		this.last = 0;
		this.max = max;
		this.step = 0;
		
		this.step = (long) max / 100;
		
		if (this.step < 100)
			this.step = -1;
		this.before = System.currentTimeMillis();
	}
	
	@Override
	public void updateProgress(long current)
	{
		if (current / step > this.last)
		{
			if (!this.quiet)
				System.out.print((int) (current * 100 / this.max) + "% done\r");
			this.last = (int) (current / step);
		}
	}
	
	@Override
	public void finishProgress()
	{
		if (!this.quiet && this.step > 1)
			System.out.println("100% done\r");
		
		long after = System.currentTimeMillis();
		if (after - this.before > 1000)
			this.verboseMessage("Time taken: " + ((double) (after - this.before) / 1000) + "s");
	}
	
	/**
	 * Defines passphrase from string
	 * 
	 * @param pwd
	 * The passphrase to be used.
	 * @throws UiResponse
	 */
	public void setPassphrase(String pwd) throws UiResponse
	{
		try
		{
			this.prePassphrase = new byte[][] { pwd.getBytes("utf-8") };
			this.preselectedPwd = 1;
		}
		catch (UnsupportedEncodingException e)
		{
			throw new UiResponse(3, e);
		}
	}
	
	/**
	 * Reads passphrase non-interactively from any input-stream.
	 * 
	 * @param in
	 * The source the passphrase is read from. If null, stdin is used.
	 * @throws UiResponse
	 */
	public void readPassphrase(InputStream in, final int numPasswords) throws UiResponse
	{
		try
		{
			InputStreamReader reader;
			if (in == null)
				reader = new InputStreamReader(new InputStream()
				// workaround since InputStreamReader buffers too much by default.
						{
							InputStream std = System.in;
							boolean streamopen = true;
							int numRead = 0;
							
							@Override
							public int read() throws IOException
							{
								if (streamopen)
								{
									int input = std.read();
									if (input == 10 || input == 13)
									{
										numRead++;
										if (numRead >= numPasswords)
										{
											streamopen = false;
											return -1;
										}
									}
									return input;
								}
								else
									return -1;
							}
						});
			else
				reader = new InputStreamReader(in);
			
			this.prePassphrase = new byte[numPasswords][0];
			
			for (int i = 0; i < numPasswords; i++)
			{
				String pwd = readLine(reader);
				this.prePassphrase[i] = pwd.getBytes("utf-8");
			}
			
			this.preselectedPwd = numPasswords;
		}
		catch (UnsupportedEncodingException e)
		{
			throw new UiResponse(3, e);
		}
	}
	
	@Override
	public byte[] getPassphrase(String ringId) throws UiResponse
	{
		
		if (this.passphrase == null || !this.ringId.equals(ringId))
		{
			this.ringId = ringId;
			if (this.prePwdRead < this.preselectedPwd)
			{
				this.passphrase = this.prePassphrase[this.prePwdRead];
				this.prePwdRead++;
				return this.passphrase;
			}
			
			if (this.disableInteractivity)
			{
				System.err.println("Passphrase required for key ring: " + ringId);
				throw new UiResponse(2);
			}
			
			String pw;
			if (this.con != null)
			{
				try
				{
					char[] input = this.con.readPassword("Enter passphrase for key ring %s: ", ringId);
					pw = new String(input);
					this.passphrase = pw.getBytes("utf-8");
				}
				catch (UnsupportedEncodingException e)
				{
					throw new UiResponse(3, e);
				}
				catch (NullPointerException e2)
				{
					throw new UiResponse(4, e2);
				}
			}
			else
			{
				System.out.print("Enter passphrase for key ring " + ringId + ": ");
				System.out.flush();
				try
				{
					pw = readLine(this.stdin);
					if (pw != null)
						this.passphrase = pw.getBytes("utf-8");
					else
						throw new UiResponse(1);
				}
				catch (UnsupportedEncodingException e1)
				{
					throw new UiResponse(3, e1);
				}
			}
		}
		
		return this.passphrase;
	}
	
	@Override
	public byte[] getNewPassphrase(String ringId) throws UiResponse
	{
		this.ringId = ringId;
		
		if (this.prePwdRead < this.preselectedPwd)
		{
			this.passphrase = this.prePassphrase[this.prePwdRead];
			this.prePwdRead++;
			return this.passphrase;
		}
		
		if (this.disableInteractivity)
		{
			System.err.println("Passphrase required for key ring: " + ringId);
			throw new UiResponse(2);
		}
		
		try
		{
			String pw = null;
			String pw1 = null;
			boolean firstrun = true;
			
			while (pw == null || !pw.equals(pw1) || pw.length() < 3)
			{
				if (!firstrun && pw.length() >= 3)
					System.out.println("Passwords did not match.");
				else if (!firstrun && pw.length() < 3)
					System.out.println("Please enter at least 3 characters.");
				
				if (this.con != null)
				{
					pw = new String(this.con.readPassword("Enter new passphrase for key ring %s: ", ringId));
					pw1 = new String(this.con.readPassword("Repeat new passphrase for key ring %s: ", ringId));
				}
				else
				{
					System.out.print("Enter new passphrase for key ring " + ringId + ": ");
					System.out.flush();
					pw = readLine(this.stdin);
					
					System.out.print("Repeat new passphrase for key ring " + ringId + ": ");
					System.out.flush();
					pw1 = readLine(this.stdin);
					
					if (pw == null || pw1 == null)
					{
						throw new UiResponse(1);
					}
				}
				firstrun = false;
			}
			
			this.passphrase = pw.getBytes("utf-8");
		}
		catch (UnsupportedEncodingException e1)
		{
			throw new UiResponse(3, e1);
		}
		
		return this.passphrase;
	}
	
	@Override
	public Boolean promptYN(String prompt, Boolean def) throws UiResponse
	{
		if (this.assumeyes)
			return true;
		
		if (this.assumeno)
			return false;
		
		System.out.print(prompt);
		
		if (this.disableInteractivity)
		{
			throw new UiResponse(2);
		}
		
		String in;
		char v;
		while (true)
		{
			if (def == null)
				System.out.print(" [y/n] ");
			else if (def.booleanValue())
				System.out.print(" [Y/n] ");
			else
				System.out.print(" [y/N] ");
			System.out.flush();
			
			in = readLine(this.stdin);
			if (in == null)
			{
				throw new UiResponse(1);
			}
			
			if (in.length() < 1)
				return def;
			else
			{
				v = in.toLowerCase().charAt(0);
				if (v == 'y')
					return true;
				else if (v == 'n')
					return false;
				else
					System.out.println("Please enter 'y' or 'n'!");
			}
			
		}
	}
	
	@Override
	public Long promptNumber(String prompt, Long def, Long min, Long max) throws UiResponse
	{
		Long n = null;
		String in;
		while (true)
		{
			System.out.print(prompt);
			if (def != null)
				System.out.print(" (Default: " + def + "): ");
			else
				System.out.print(": ");
			
			System.out.flush();
			try
			{
				in = readLine(this.stdin);
				
				if (in == null)
				{
					throw new UiResponse(1);
				}
				
				if (in.length() == 0)
					return def;
				
				n = Long.decode(in);
			}
			catch (NumberFormatException e)
			{
				n = (long) -1;
			}
			
			if ((min == null || n >= min) && (max == null || n <= max))
				return n;
			else
			{
				if (max == null)
					System.out.println("Please enter a number >= " + min);
				else if (min == null)
					System.out.println("Please enter a number <= " + max);
				else
					System.out.println("Please enter a number between " + min + " and " + max);
			}
		}
	}
	
	@Override
	public String promptStr(String prompt, String def) throws UiResponse
	{
		String in;
		
		System.out.print(prompt);
		if (def != null)
			System.out.print(" (Default: " + def + "): ");
		else
			System.out.print(": ");
		
		System.out.flush();
		in = readLine(this.stdin);
		if (in == null)
		{
			throw new UiResponse(1);
		}
		else if (in.equals(""))
		{
			return def;
		}
		else
			return in;
	}
	
	@Override
	public void verboseMessage(String message)
	{
		if (this.verbose)
			System.out.println(message);
	}
	
	@Override
	public void message(String message)
	{
		if (!this.quiet)
			System.out.println(message);
	}
	
	@Override
	public void warningMessage(String message)
	{
		System.err.println(message);
	}
	
	private String readLine(InputStreamReader in)
	{
		StringBuilder sb = new StringBuilder();
		boolean eol = false;
		int read;
		while (!eol)
		{
			try
			{
				char ac[] = new char[1];
				read = in.read(ac, 0, 1);
				if (read == -1 || ac[0] == '\n' || ac[0] == '\r')
					eol = true;
				else
					sb.append(ac);
			}
			catch (IOException e)
			{
				eol = true;
			}
		}
		return sb.toString();
	}
}
