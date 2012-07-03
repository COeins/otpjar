import otp.Infile;
import otp.OtpWorker;
import otp.Outfile;
import otp.Result;
import otp.Rng;
import otp.UserInterface;
import otp.impl.ArmoredInfile;
import otp.impl.ArmoredOutfile;
import otp.impl.BaInfile;
import otp.impl.CommandLineUI;
import otp.impl.InfileRNG;
import otp.impl.LocalInfile;
import otp.impl.LocalOutfile;
import otp.impl.PseudoRNG;
import otp.impl.RealKeyRing;
import otp.impl.RealOtp;
import otp.impl.WegCarAuth;
import otp.impl.stdInfile;
import otp.impl.stdOutfile;
import otp.response.KeyringResponse;
import otp.response.Response;
import otp.response.RngResponse;
import otp.response.UiResponse;
import otp.response.WorkResponse;

public class OtpCmdLine
{
	
	private static final String ver = "0.2.1.0";
	
	static final int PARAM_INFILE = 1;
	static final int PARAM_INFILE2 = 2;
	static final int PARAM_OUTFILE = 3;
	static final int PARAM_RNGFILE = 4;
	static final int PARAM_RINGID = 5;
	static final int PARAM_KEYID = 6;
	static final int PARAM_KEYPATH = 7;
	static final int PARAM_BASEPATH = 8;
	static final int PARAM_PASSPHRASE = 9;
	static final int PARAM_KEYFILE = 10;
	static final int PARAM_PASSPHRASE_NUM = 11;
	
	public static void main(String[] args)
	{
		
		char action = 'h';
		String input = null;
		String input2 = null;
		String output = null;
		String keyid = null;
		String ringid = null;
		String keypath = null;
		String basepath = null;
		String keyfile = null;
		boolean armor = false;
		boolean verbose = false;
		int stdpassphrase = 0;
		
		int paramfollows = 0;
		CommandLineUI ui = new CommandLineUI();
		Rng rng = new PseudoRNG(ui);
		
		for (int i = 0; i < args.length; i++)
		{
			int param = paramfollows;
			paramfollows = 0;
			
			// actions
			if (args[i].equals("--help") || args[i].equals("-h") || args[i].equals("/?"))
			{
				action = 'h';
			}
			else if (args[i].equals("--encrypt") || args[i].equals("-e"))
			{
				action = 'e';
				paramfollows = PARAM_INFILE;
			}
			else if (args[i].equals("--decrypt") || args[i].equals("-d"))
			{
				action = 'd';
				paramfollows = PARAM_INFILE;
			}
			else if (args[i].equals("--sign") || args[i].equals("-s"))
			{
				action = 's';
				paramfollows = PARAM_INFILE;
			}
			else if (args[i].equals("--verify") || args[i].equals("-y"))
			{
				action = 'v';
				paramfollows = PARAM_INFILE;
			}
			
			// key management
			else if (args[i].equals("--list-keys"))
			{
				action = 'l';
			}
			else if (args[i].equals("--gen-key"))
			{
				action = 'g';
			}
			else if (args[i].equals("--edit-key"))
			{
				action = 'p';
				paramfollows = PARAM_KEYID;
			}
			else if (args[i].equals("--modify-key"))
			{
				action = 'm';
				paramfollows = PARAM_INFILE2;
			}
			else if (args[i].equals("--key-info"))
			{
				action = 'n';
				paramfollows = PARAM_KEYID;
			}
			else if (args[i].equals("--delete-key"))
			{
				action = 't';
				paramfollows = PARAM_KEYID;
			}
			else if (args[i].equals("--export"))
			{
				action = 'x';
				paramfollows = PARAM_KEYFILE;
			}
			else if (args[i].equals("--import"))
			{
				action = 'i';
				paramfollows = PARAM_KEYFILE;
			}
			else if (args[i].equals("--request-sync"))
			{
				action = 'q';
				paramfollows = PARAM_KEYID;
			}
			else if (args[i].equals("--syncronize"))
			{
				action = 'y';
				paramfollows = PARAM_KEYID;
			}
			// options
			else if (args[i].equals("--armor") || args[i].equals("-a"))
			{
				armor = true;
			}
			else if (args[i].equals("--outfile") || args[i].equals("-o"))
			{
				paramfollows = PARAM_OUTFILE;
			}
			else if (args[i].equals("--key") || args[i].equals("-k"))
			{
				paramfollows = PARAM_KEYID;
			}
			else if (args[i].equals("--ring") || args[i].equals("-r"))
			{
				paramfollows = PARAM_RINGID;
			}
			else if (args[i].equals("--rngfile"))
			{
				paramfollows = PARAM_RNGFILE;
			}
			else if (args[i].equals("--otplocation"))
			{
				paramfollows = PARAM_KEYPATH;
			}
			else if (args[i].equals("--basedir"))
			{
				paramfollows = PARAM_BASEPATH;
			}
			else if (args[i].equals("--passphrase"))
			{
				paramfollows = PARAM_PASSPHRASE;
			}
			else if (args[i].equals("--passphrase-stdin"))
			{
				stdpassphrase = 1;
				paramfollows = PARAM_PASSPHRASE_NUM;
			}
			else if (args[i].equals("--verbose") || args[i].equals("-v"))
			{
				ui.setVerbose();
				verbose = true;
			}
			else if (args[i].equals("--quiet") || args[i].equals("-q"))
			{
				ui.setQuiet();
			}
			else if (args[i].equals("--yes"))
			{
				ui.setYes();
			}
			else if (args[i].equals("--no"))
			{
				ui.setNo();
			}
			else if (args[i].equals("--no-interactivity"))
			{
				ui.disableInteractivity();
			}
			else if (param > 0)
			{
				switch (param)
				{
					case PARAM_INFILE:
						input = args[i];
						break;
					case PARAM_INFILE2:
						input2 = args[i];
						paramfollows = PARAM_INFILE;
						break;
					case PARAM_OUTFILE:
						output = args[i];
						break;
					case PARAM_RNGFILE:
						rng = new InfileRNG(args[i], rng, ui);
						break;
					case PARAM_RINGID:
						ringid = args[i];
						break;
					case PARAM_KEYID:
						keyid = args[i];
						break;
					case PARAM_KEYPATH:
						keypath = args[i];
						break;
					case PARAM_BASEPATH:
						basepath = args[i];
						break;
					case PARAM_PASSPHRASE:
						try
						{
							ui.setPassphrase(args[i]);
						}
						catch (UiResponse e)
						{
							System.err.println(e.getMessage());
							System.exit(255);
						}
						break;
					case PARAM_PASSPHRASE_NUM:
						stdpassphrase = new Integer(args[i]);
						break;
					case PARAM_KEYFILE:
						keyfile = args[i];
						break;
				}
			}
			else
			{
				ui.warningMessage("Invalid command detectet. Use --help to see a list of valid commands.");
				System.exit(254);
			}
		}
		
		try
		{
			if (stdpassphrase > 0)
				ui.readPassphrase(null, stdpassphrase);
		}
		catch (UiResponse e)
		{
			System.err.println(e.getMessage());
			System.exit(255);
		}
		
		RealKeyRing keyring = new RealKeyRing(rng, ui);
		
		if (keypath != null)
			keyring.overwritePath(keypath);
		if (basepath != null)
			keyring.setBasePath(basepath);
		
		if (ringid != null)
		{
			if (!keyring.selectKeyRing(ringid))
				ui.warningMessage("Key-ring id '" + ringid +
						"' is in wrong format, please enter as 8-digit hexadecimal number.");
		}
		
		Infile in;
		Outfile out;
		
		if (input != null)
		{
			in = new LocalInfile(input);
		}
		else
		{
			in = new stdInfile();
		}
		
		if (output != null)
		{
			out = new LocalOutfile(output, ui);
		}
		else
		{
			out = new stdOutfile();
		}
		
		Result res = null;
		
		switch (action)
		{
			case 'e': // encrypt
				res = OtpCmdLine.encrypt(ui, keyring, keyid, in, out, armor, rng);
				break;
			
			case 'd': // decrypt
				if (keyid != null)
					ui.message("Key-id given unnecessarily, will be ignored.");
				
				res = OtpCmdLine.decrypt(ui, keyring, in, out, rng);
				break;
			
			case 'm': // modify key
				if (keyid != null)
					ui.message("Key-id given unnecessarily, will be ignored.");
				
				Infile oldin = null;
				if (input2 != null)
				{
					oldin = new LocalInfile(input2);
				}
				else
				{
					oldin = in;
					in = null;
				}
				// else
				// ui.warningMessage("Please enter two filenames: '--modify-key <ciphertext file> <new plaintext file>'");
				
				res = OtpCmdLine.modifyKey(ui, keyring, oldin, in, rng);
				break;
			
			case 's': // sign
				ui.warningMessage("Not yet implemented");
				break;
			
			case 'v': // verify
				ui.warningMessage("Not yet implemented");
				break;
			
			case 'l': // list keys
				res = OtpCmdLine.listKeys(ui, keyring);
				break;
			
			case 'g': // generate key
				if (keyid != null)
					ui.message("Key-id given unnecessarily, will be ignored.");
				res = OtpCmdLine.generateKey(ui, keyring, rng);
				break;
			
			case 't': // delete key
				ui.warningMessage("Not yet implemented");
				break;
			
			case 'p': // edit key / change passphrase or alias
				res = OtpCmdLine.editKey(ui, keyring, keyid, rng);
				break;
			
			case 'n': // info page
				res = OtpCmdLine.keyInfo(ui, keyring, keyid);
				break;
			
			case 'q': // reuest keysync
				res = OtpCmdLine.syncReq(ui, keyring, keyid, out, armor, rng);
				break;
			
			case 'y': // send keysync
				res = OtpCmdLine.syncAck(ui, keyring, keyid, out, armor, rng);
				break;
			
			case 'x': // export key
				res = OtpCmdLine.exportKey(ui, keyring, keyid, keyfile, rng);
				break;
			
			case 'i': // import key
				res = OtpCmdLine.importKey(ui, keyring, keyfile, rng);
				break;
			
			case 'h': // help
				res = help(ui);
				break;
			
			default:
				ui.warningMessage("No command detectet. Use --help to see a list of valid commands.");
				System.exit(1);
		}
		
		if (res == null)
			res = new Result(new WorkResponse(0));
		
		if (res.getSuccess())
		{
			int ex = res.getExitCode();
			if (ex > 0)
			{
				for (Response r : res.getErrors())
				{
					ui.warningMessage(r.getMessage());
				}
			}
			else
			{
				ui.verboseMessage("Finished successfully.");
			}
			System.exit(ex);
		}
		else
		{
			for (Response r : res.getErrors())
			{
				if (verbose)
					r.printStackTrace();
				
				while (r.getCause() instanceof Response)
				{
					if (verbose)
						ui.warningMessage(r.getMessage());
					r = (Response) r.getCause();
				}
				ui.warningMessage(r.getMessage());
				// ui.verboseMessage("\nCanceled.");
				System.exit(r.getExitCode());
			}
		}
	}
	
	public static Result encrypt(UserInterface ui, RealKeyRing keyring, String key, Infile in, Outfile out,
			boolean armor, Rng rng)
	{
		Result res;
		ui.message("Encrypting...");
		
		if (!keyring.selectKey(key))
		{
			ui.warningMessage("Please use the '--key' parameter so specify the key id (as 8-digit hex number) or alias to be used!");
			return new Result(new WorkResponse(0));
		}
		
		if (in == null)
		{
			ui.warningMessage("Please enter the input file name!");
			return new Result(new WorkResponse(0));
		}
		
		RealOtp eotp = new RealOtp(keyring, ui);
		RealOtp aotp = new RealOtp(keyring, ui);
		WegCarAuth auth = new WegCarAuth(keyring, aotp);
		Outfile out1 = armor ? new ArmoredOutfile(out) : out;
		res = OtpWorker.encrypt(keyring, in, out1, eotp, aotp, auth, rng, ui);
		return res;
	}
	
	public static Result syncReq(UserInterface ui, RealKeyRing keyring, String key, Outfile out, boolean armor, Rng rng)
	{
		Result res = null;
		ui.message("Creating sync request...");
		
		if (!keyring.selectKey(key))
		{
			ui.warningMessage("Please use the '--key' parameter so specify the key id (as 8-digit hex number) or alias to be used!");
			return new Result(new WorkResponse(0));
		}
		
		RealOtp eotp = new RealOtp(keyring, ui);
		RealOtp aotp = new RealOtp(keyring, ui);
		WegCarAuth auth = new WegCarAuth(keyring, aotp);
		Outfile out1 = armor ? new ArmoredOutfile(out) : out;
		
		res = OtpWorker.createSyncReq(keyring, out1, eotp, aotp, auth, rng, ui);
		
		return res;
	}
	
	public static Result syncAck(UserInterface ui, RealKeyRing keyring, String key, Outfile out, boolean armor, Rng rng)
	{
		Result res = null;
		ui.message("Creating sync message...");
		
		if (!keyring.selectKey(key))
		{
			ui.warningMessage("Please use the '--key' parameter so specify the key id (as 8-digit hex number) or alias to be used!");
			return new Result(new WorkResponse(0));
		}
		
		RealOtp eotp = new RealOtp(keyring, ui);
		RealOtp aotp = new RealOtp(keyring, ui);
		WegCarAuth auth = new WegCarAuth(keyring, aotp);
		Outfile out1 = armor ? new ArmoredOutfile(out) : out;
		
		res = OtpWorker.createSyncAck(keyring, out1, eotp, aotp, auth, rng, ui);
		
		return res;
	}
	
	public static Result decrypt(UserInterface ui, RealKeyRing keyring, Infile in, Outfile out, Rng rng)
	{
		Result res = null;
		boolean tryagain = false;
		
		if (in == null)
		{
			ui.warningMessage("Please enter the input file name!");
			return new Result(new WorkResponse(0));
		}
		
		ui.message("Verifying...");
		
		Infile in2 = in;
		RealOtp eotp = new RealOtp(keyring, ui);
		RealOtp aotp = new RealOtp(keyring, ui);
		WegCarAuth auth = new WegCarAuth(keyring, aotp);
		boolean[] msginfo = new boolean[2];
		
		res = OtpWorker.verify(keyring, in2, aotp, auth, rng, ui, msginfo);
		
		if (!res.getSuccess())
		{
			for (Response r : res.getErrors())
			{
				if (r instanceof WorkResponse && r.getErrorCode() == 1)
					tryagain = true;
			}
		}
		
		if (tryagain)
		{
			in2 = new ArmoredInfile(in);
			res = OtpWorker.verify(keyring, in2, aotp, auth, rng, ui, msginfo);
		}
		
		if (res.getSuccess())
		{
			ui.message("Decrypting...");
			res = OtpWorker.decrypt(keyring, in2, out, eotp, aotp, auth, rng, ui, msginfo[1]);
		}
		
		return res;
	}
	
	public static Result modifyKey(UserInterface ui, RealKeyRing keyring, Infile oldin, Infile newin, Rng rng)
	{
		
		ui.message("Modifying key...");
		
		RealOtp eotp = new RealOtp(keyring, ui);
		RealOtp aotp = new RealOtp(keyring, ui);
		WegCarAuth auth = new WegCarAuth(keyring, aotp);
		Result res = null;
		boolean tryagain = false;
		
		if (newin == null)
			tryagain = true;
		else
		{
			res = OtpWorker.modifyKey(keyring, oldin, newin, eotp, aotp, auth, rng, ui);
			
			if (!res.getSuccess())
			{
				for (Response r : res.getErrors())
				{
					if (r instanceof WorkResponse && r.getErrorCode() == 1)
						tryagain = true;
				}
			}
		}
		
		if (tryagain)
		{
			if (newin == null)
			{
				BaInfile bain = new BaInfile(null);
				oldin = new ArmoredInfile(oldin, bain);
				newin = bain;
			}
			else
				oldin = new ArmoredInfile(oldin);
			
			res = OtpWorker.modifyKey(keyring, oldin, newin, eotp, aotp, auth, rng, ui);
		}
		
		return res;
	}
	
	public static Result listKeys(UserInterface ui, RealKeyRing keyring)
	{
		Result res = new Result();
		try
		{
			keyring.listInstalledKeys();
			
		}
		catch (Response r)
		{
			res.add(new WorkResponse(0, r));
		}
		res.add(new WorkResponse(true));
		
		return res;
	}
	
	public static Result generateKey(UserInterface ui, RealKeyRing keyring, Rng rng)
	{
		ui.message("Generating Key...");
		Result res = new Result();
		RealOtp otp = new RealOtp(keyring, rng, ui);
		boolean success = false;
		
		try
		{
			rng.initialize();
			
			Long l = ui.promptNumber("Please enter OTP size (in Mbytes)", null, (long) 1, null);
			if (l == null)
				throw new WorkResponse(4);
			long padsize = l * 1024 * 1024;
			
			String alias = ui.promptStr("Please choose the key alias", null);
			int iterations = 3;
			int paddingP1 = 128;
			int paddingP2 = 70;
			int authlength = 32;
			int identByteCount = 64;
			
			// default between 8192 and 64 blocks
			int blocks = (int) Math.pow(2, Math.ceil(Math.log(Math.min(Math.max(64, (l * 8)), 8 * 1024)) / Math.log(2)));
			int blocksize = (int) (padsize / blocks);
			
			// default window: 1MB, but max pad/16
			long windowsize = Math.min(1024 * 1024, (int) (padsize / 16));
			long warningsize = Math.min(2048 * 1024, (int) (padsize / 32));
			
			if (!ui.promptYN("Use key parameter default values? ", true))
			{
				l = ui.promptNumber("Please enter OTP block size (in kbytes)", (long) blocksize / 1024, 1L, null);
				if (l == null)
					throw new WorkResponse(4);
				blocksize = l.intValue() * 1024;
				
				l = ui.promptNumber("Please enter OTP window size (in kbytes)", windowsize / 1024, 1L, null);
				if (l == null)
					throw new WorkResponse(4);
				windowsize = l.intValue() * 1024;
				
				l = ui.promptNumber("OTP generation iterations", (long) iterations, 1L, null);
				if (l == null || l == 0)
					throw new WorkResponse(4);
				iterations = l.intValue();
				
				l = ui.promptNumber("Please enter the number of identification bytes", (long) identByteCount, 32L, null);
				if (l == null)
					throw new WorkResponse(4);
				identByteCount = l.intValue();
				
				l = ui.promptNumber("Please enter message padding median (in bytes)", (long) paddingP1, 0L, null);
				if (l == null)
					throw new WorkResponse(4);
				paddingP1 = l.intValue();
				
				l = ui.promptNumber("Please enter message padding distribution (in 1/100)", (long) paddingP2, 0L, null);
				if (l == null)
					throw new WorkResponse(4);
				paddingP2 = l.intValue();
				
				l = ui.promptNumber("Please enter message authentication code length (in bytes)", (long) authlength, 1L, null);
				if (l == null)
					throw new WorkResponse(4);
				authlength = l.intValue();
				
				l = ui.promptNumber("Please enter low-pad warning threshold (in kbytes)", warningsize / 1024);
				if (l == null)
					throw new WorkResponse(4);
				warningsize = l * 1024;
			}
			
			// fit blocksize to encryption block size
			blocksize = (blocksize / 16) * 16;
			
			// round pad size down to nearest block multiple
			padsize = (padsize / blocksize) * blocksize;
			
			keyring.createKey(padsize, blocksize, windowsize, warningsize, identByteCount, paddingP1, paddingP2, authlength,
					alias);
			otp.createPad(iterations);
			success = true;
			// keyring.finish(success);
		}
		catch (Response r)
		{
			res.add(new WorkResponse(0, r));
		}
		finally
		{
			res.add(keyring.finish(success));
			res.add(otp.finish(success));
			res.add(rng.finish(success));
			res.add(new WorkResponse(true));
		}
		
		return res;
	}
	
	public static Result editKey(UserInterface ui, RealKeyRing keyring, String key, Rng rng)
	{
		Result res = new Result();
		boolean success = false;
		
		if (!keyring.selectKey(key))
		{
			ui.warningMessage("Please use the '--key' parameter so specify the key id (as 8-digit hex number) or alias to be used!");
			return new Result(new WorkResponse(0));
		}
		
		try
		{
			ui.message("(1) Edit key ring passphrase");
			ui.message("(2) Edit key alias");
			Long menu = ui.promptNumber("Please choose task", null, 1L, 2L);
			
			if (menu.intValue() == 1)
			{
				ui.message("Warning this change will affect all keys in this key ring.");
				
				rng.initialize();
				keyring.initialize();
				
				keyring.changePwd();
				success = true;
			}
			else if (menu.intValue() == 2)
			{
				rng.initialize();
				keyring.initialize();
				
				String alias = ui.promptStr("Please enter new alias", null);
				
				if (alias != null)
					keyring.keyChangeAlias(alias);
				
				success = true;
			}
		}
		catch (RngResponse e)
		{
			res.add(new WorkResponse(0, e));
		}
		catch (KeyringResponse e)
		{
			res.add(new WorkResponse(0, e));
		}
		catch (UiResponse e)
		{
			res.add(new WorkResponse(0, e));
		}
		finally
		{
			res.add(keyring.finish(success));
			res.add(rng.finish(success));
			res.add(new WorkResponse(true));
		}
		return res;
	}
	
	public static Result keyInfo(UserInterface ui, RealKeyRing keyring, String key)
	{
		ui.message("Key Information:");
		Result res = new Result();
		
		if (!keyring.selectKey(key))
		{
			ui.warningMessage("Please use the '--key' parameter so specify the key id (as 8-digit hex number) or alias to be used!");
			return new Result(new WorkResponse(0));
		}
		
		try
		{
			keyring.initialize();
			keyring.displayKeyInfo();
			keyring.finish(true);
		}
		catch (KeyringResponse e)
		{
			res.add(new WorkResponse(0, e));
		}
		finally
		{
			res.add(keyring.finish(true));
			res.add(new WorkResponse(true));
		}
		return res;
	}
	
	public static Result exportKey(UserInterface ui, RealKeyRing keyring, String key, String outdir, Rng rng)
	{
		ui.message("Exporting key...");
		Result res = new Result();
		RealOtp otp = new RealOtp(keyring, rng, ui);
		boolean success = false;
		
		if (!keyring.selectKey(key))
		{
			ui.warningMessage("Please use the '--key' parameter so specify the key id (as 8-digit hex number) or alias to be used!");
			return new Result(new WorkResponse(0));
		}
		
		try
		{
			keyring.selectKey(key);
			rng.initialize();
			keyring.initialize();
			otp.initialize();
			
			if (keyring.getKeyOwner() == 1 &&
					!ui.promptYN(
							"This key looks like it was not created on this computer. Exporting it from here could lead to inconsistencies. Continue anyway?",
							false))
				throw new WorkResponse(4);
			
			keyring.exportKeyData(outdir);
			
			ui.message("Writing key file...");
			otp.reencrypt();
			success = true;
		}
		catch (WorkResponse w)
		{
			res.add(w);
		}
		catch (Response r)
		{
			res.add(new WorkResponse(0, r));
		}
		finally
		{
			res.add(otp.finish(success));
			res.add(keyring.finish(success));
			res.add(rng.finish(success));
			res.add(new WorkResponse(true));
		}
		
		return res;
	}
	
	public static Result importKey(UserInterface ui, RealKeyRing keyring, String keyfile, Rng rng)
	{
		ui.message("Importing key...");
		Result res = new Result();
		RealOtp otp = new RealOtp(keyring, rng, ui);
		boolean success = false;
		
		if (keyfile == null)
		{
			ui.warningMessage("Please specify the *.key file to be imported.");
			return new Result(new WorkResponse(0));
		}
		
		try
		{
			rng.initialize();
			keyring.loadExternalKeyData(keyfile);
			otp.initialize();
			String alias = ui.promptStr("Please choose a new alias for this key", null);
			
			keyring.importKeyData();
			if (alias != null)
				keyring.keyChangeAlias(alias);
			
			ui.message("Writing key file...");
			otp.reencrypt();
			success = true;
		}
		catch (Response r)
		{
			res.add(new WorkResponse(0, r));
		}
		finally
		{
			res.add(otp.finish(success));
			res.add(keyring.finish(success));
			res.add(rng.finish(success));
			res.add(new WorkResponse(true));
		}
		return res;
	}
	
	public static Result help(UserInterface ui)
	{
		String[] h = new String[] {
				"OTP " + OtpCmdLine.ver,
				"",
				"Usage:",
				"java -jar otp.jar [command] [arg] [options]",
				"",
				"Commands: (exactly one has to be used)",
				"-e, --encrypt <filename>	Encrypts the specified file",
				"-d, --decrypt <filename>	Decrypts the specified file",
				// "-s, --sign <filename>	Signs the specified file",
				// "-y, --verify <filename>  Verifies the specified file",
				" (If no filename is given stdin is used by default)",
				"",
				"--gen-key			Generates new OTP key",
				"--export <path>			Exports a key key the specified path",
				"--import <path/file.key>	Imports the specified key from 'filename.key'",
				"--edit-key <key-id>		Changes the passphrase or alias",
				// "--delete-key <key-id>		Deletes the specified key",
				"--modify-key <ciphertext> <new plaintext>	Generates a new plaintext for a given ciphertext",
				"--request-sync <key-id>		Generate synchronisation request message",
				"--syncronize <key-id>		Generate key synchronisation message",
				"--key-info <key-id>		Displays the key status page (combine with -v for details)", "",
				"--list-keys			Lists all locally installed keys", "-h, --help			Display this help page", "",
				"Options: (several may be combined)", "-a, --armor			Use ascii-armored output (for e-mail)",
				"-o, --outfile <filename>	Write Output to 'filename' instead of stdout",
				"-k, --key <key-id>		Use specfied key for encryption or export, as id or alias",
				"-r, --ring <ring-id>		Specify key-ring id, may be 'new' for generated or imported keys",
				"--otplocation <path/file.pad> 	Specify new OTP location",
				"--rngfile <path/file>		Specify source file for random numbers",
				"--basedir <path>		Change default location for keys and settings", "--passphrase <pwd>		Use given passphrase",
				"--passphrase-stdin <num>	Read passphrase from stdin (before reading any other input)", "",
				"-v, --verbose			Verbose status messages", "-q, --quiet			Less status messages",
				"--yes / --no			Assume yes/no on confirmation questions", "", "" };
		
		for (String s : h)
			ui.message(s);
		
		return new Result(new WorkResponse(true));
	}
	
}
