package otp.impl;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import otp.KeyRing;
import otp.Rng;
import otp.UserInterface;
import otp.helpr.BlockAssignList;
import otp.helpr.BlockData;
import otp.helpr.BlockPlan;
import otp.helpr.ByteArray;
import otp.helpr.ByteArrayBuilder;
import otp.helpr.IniFileParser;
import otp.helpr.KnownMsgs;
import otp.response.KeyringResponse;
import otp.response.RngResponse;
import otp.response.UiResponse;

/**
 * KeySettings module for use with local encrypted key file
 */
public class RealKeyRing extends KeyRing
{
	
	// modules
	private Rng rng;
	private UserInterface ui;
	
	private String cacheFileName = "keys.ini";
	private IniFileParser cacheSettings;
	
	private RandomAccessFile ringFile;
	private byte[] ringSalt = new byte[8];
	private Key ringKey;
	private IvParameterSpec ringIv;
	private IniFileParser ringSettings;
	
	private Map<Integer, BlockData> blockDataCache = new HashMap<Integer, BlockData>();
	
	// global properties
	private boolean createNewRing;
	private byte[] ringId;
	private byte[] keyId;
	private String basePath;
	private int participant = -1;
	private long lastAction;
	private final long lastActionWarnThreshold = 1000 * 60 * 60 * 24 * 14;
	// 2 weeks in 1000th seconds
	
	// private final int identByteCount = 64;
	
	private boolean initialized = false;
	private boolean dirty = false;
	private boolean forceupdate = false;
	
	// key settings...
	private int keyOwner = -1;
	private String keyAlias;
	// private boolean keyIsValid = false;
	private boolean keyOutOfSync = false;
	private BlockPlan[] partnerPlan = new BlockPlan[(KeyRing.BLOCKTYPE_A | 1) + 1];
	
	private long keyWarnSize = -1;
	private long keyWindowSize = -1;
	
	private KnownMsgs keyKnownMsgs;
	private String otpPath;
	private File otpFile;
	private String otpPathOverwrite;
	private byte[] otpKey;
	private byte[] otpIv;
	
	private byte[] otpIdentBytes;
	private int[][] otpIdentPos;
	
	private int otpBlockSize = -1;
	private int otpBlockCount = -1;
	
	private BlockAssignList[] otpBlocks;
	private BlockPlan[] otpPlan;
	
	private int paddParam1 = -1;
	private int paddParam2 = -1;
	private String authMethod;
	private int authLen = -1;
	
	private boolean importing = false;
	private boolean generatedOrImported = false;
	private boolean exported = false;
	
	/**
	 * Creates new RealKeyRing
	 * 
	 * @param random
	 * Rng module used for settings encryption
	 * @param ui
	 * UserInterface for status messages
	 */
	public RealKeyRing(Rng random, UserInterface ui)
	{
		this.rng = random;
		this.ui = ui;
	}
	
	public boolean selectKeyRing(String ringId)
	{
		if (this.initialized || ringId == null)
			return false;
		
		if (ringId.equals("new"))
		{
			this.createNewRing = true;
			return true;
		}
		
		try
		{
			byte[] rid = ByteArray.fromHex(ringId);
			if (rid.length == 4)
			{
				this.ringId = rid;
				return true;
			}
			else
				return false;
		}
		catch (NumberFormatException e)
		{
			return false;
		}
	}
	
	public boolean selectKey(String keyIdOrAlias) // throws KeyringResponse
	{
		if (this.initialized || keyIdOrAlias == null || keyIdOrAlias.length() < 1)
			return false;
		
		// System.out.print("Searching key or alias '"+keyIdOrAlias+"'...");
		
		try
		{
			byte[] kid = ByteArray.fromHex(keyIdOrAlias);
			if (kid.length == 4)
			{
				this.keyId = kid;
				// System.out.print("4-byte hex number recognized as key-id.");
				return true;
			}
		}
		catch (NumberFormatException e)
		{
		}
		
		try
		{
			this.readCache();
		}
		catch (KeyringResponse e1)
		{
			// System.out.print("Error reading ini-file. Cancelling...");
			return false;
		}
		
		for (String s : this.cacheSettings.getSections())
		{
			// System.out.println("Comparing alias for key '"+s+"': '"+this.cacheSettings.getValueString(s,
			// "keyAlias")+"' == '"+keyIdOrAlias+"'?");
			
			if (keyIdOrAlias.equals(this.cacheSettings.getValueString(s, "keyAlias")))
			{
				this.ui.message("Found key " + s + " for alias '" + keyIdOrAlias + "'");
				this.keyId = ByteArray.fromHex(s);
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Selects the key and participant to be used, for use with decryption
	 */
	@Override
	public void selectKey(byte[] keyId, int participant)
	{
		if (!this.initialized)
		{
			this.keyId = keyId;
			this.participant = participant;
		}
	}
	
	/**
	 * Selects an alternative location for the corresponding *.pad file. The user
	 * will be prompted to save that new location as default.
	 * 
	 * @param path
	 * Directory and filename of the OTP file to be used.
	 */
	public void overwritePath(String path)
	{
		this.otpPathOverwrite = path;
	}
	
	/**
	 * Allows the key files to be stored on a location different than the
	 * currently active path
	 * 
	 * @param basepath
	 * The location where key files should be searched
	 */
	public void setBasePath(String basepath)
	{
		this.basePath = basepath;
	}
	
	@Override
	public void initialize() throws KeyringResponse
	{
		if (this.initialized)
			return;
		
		if (this.keyId == null)
			throw new KeyringResponse(0);
		if (keyId.length != 4)
			throw new KeyringResponse(0);
		
		File sf = this.getRingFile();
		if (!sf.exists())
		{
			this.ui.warningMessage("Keyring file " + sf.getAbsolutePath() + " missing.");
			throw new KeyringResponse(2);
		}
		if (!sf.canWrite())
			throw new KeyringResponse(4);
		
		try
		{
			this.ringFile = new RandomAccessFile(sf, "rwd");
			this.readSettings();
			if (this.participant == -1)
				this.participant = this.keyOwner;
		}
		catch (FileNotFoundException e)
		{
			throw new KeyringResponse(2, e);
		}
		
		String padfile;
		
		if (this.otpPathOverwrite != null) // specific override
			padfile = this.otpPathOverwrite;
		else if (this.basePath != null) // global override
			if (!this.otpPath.contains(File.separator))
				padfile = this.basePath + File.separator + this.otpPath;
			else
				padfile = this.otpPath;
		else
			padfile = this.otpPath;
		
		this.otpFile = new File(padfile);
		
		if (!this.otpFile.canRead())
		{
			this.ui.warningMessage("OTP file " + this.otpFile.getAbsolutePath() +
					" not found. Please use '--otplocation' to specify path!");
			throw new KeyringResponse(7);
		}
		
		this.initialized = true;
		this.updateLastAction();
	}
	
	/**
	 * Creates a new OTP key
	 * 
	 * @param otpSize
	 * The total size of the new OTP
	 * @param blockSize
	 * The size of each block
	 * @param windowSize
	 * The size of the sending windows. Must not be greater 1/16th of the OTP
	 * @param warningSize
	 * A warning will be given if less then this value is available
	 * @param identByteCount
	 * The number of bytes checked on each encryption run
	 * @param paddParam1
	 * The padding median
	 * @param paddParam2
	 * The padding distribution (as 1/100th)
	 * @param authlength
	 * The length of the authentication code
	 * @param alias
	 * The key alias name
	 * @throws KeyringResponse
	 */
	public void createKey(long otpSize, int blockSize, long windowSize, long warningSize, int identByteCount,
			int paddParam1, int paddParam2, int authlength, String alias) throws KeyringResponse
	{
		try
		{
			if (this.cacheSettings == null)
				this.readCache();
			
			if (this.ringId == null && !this.createNewRing)
			{
				String rid = this.cacheSettings.getValueString(null, "defaultKeyRing");
				if (rid != null)
					this.ringId = ByteArray.fromHex(rid);
			}
			
			if (this.ringId == null || this.createNewRing)
			{
				this.ringId = this.rng.next(4);
				this.cacheSettings.setValue(null, "defaultKeyRing", ByteArray.toHex(this.ringId));
			}
			
			String hexkey;
			do
			{
				this.keyId = this.rng.next(4);
				hexkey = ByteArray.toHex(this.keyId);
			}
			while (this.cacheSettings.getSections().contains(hexkey));
			
			String hexring = ByteArray.toHex(this.ringId);
			
			File sf = this.getRingFile();
			
			if (sf.exists() && sf.length() > 0)
			{
				// load existing ring
				try
				{
					this.ringFile = new RandomAccessFile(sf, "rwd");
					ui.verboseMessage("Loading ring " + hexring);
					this.generatedOrImported = true;
					this.readSettings();
				}
				catch (KeyringResponse e)
				{
					if (e.getErrorCode() != 1)
						throw e;
				}
			}
			else
			{
				ui.message("Creating new key ring: " + hexring);
				// create ring
				
				this.ringFile = new RandomAccessFile(sf, "rwd");
				this.ringSettings = new IniFileParser();
				this.ringSettings.setValue(null, "keyRingId", hexring);
				this.rng.next(this.ringSalt);
				byte[] pw = this.ui.getNewPassphrase(hexring);
				if (pw.length < 3)
					throw new KeyringResponse(8);
				byte[] keys = this.pwdToKey(pw, 48);
				
				this.ringKey = new SecretKeySpec(keys, 0, 16, "AES");
				this.ringIv = new IvParameterSpec(keys, 16, 16);
			}
			if (!sf.canWrite())
				throw new KeyringResponse(4);
			
			ui.message("Creating new key: " + hexkey);
			
			this.participant = 0;
			this.keyOwner = 0;
			this.keyAlias = alias == null ? "" : alias;
			// this.keyIsValid = true;
			this.keyOutOfSync = false;
			
			if (this.otpPathOverwrite != null) // specific override
			{
				this.otpPath = this.otpPathOverwrite;
				this.otpPathOverwrite = null;
			}
			else
				this.otpPath = hexkey + ".pad";
			
			if (this.basePath == null || this.otpPath.contains(File.separator))
				this.otpFile = new File(this.otpPath);
			else
				this.otpFile = new File(this.basePath + File.separator + this.otpPath);
			
			this.otpKey = this.rng.next(16);
			this.otpIv = this.rng.next(16);
			
			this.otpBlockSize = blockSize;
			this.otpBlockCount = (int) Math.ceil((double) otpSize / (double) blockSize);
			
			if (this.otpBlockCount < 8)
			{
				ui.warningMessage("OTP must contain of at least 8 blocks.");
				throw new KeyringResponse(0);
			}
			if (windowSize > otpSize / 8)
			{
				ui.warningMessage("Window size must not be greater then 1/8th of OTP.");
				throw new KeyringResponse(0);
			}
			
			this.otpIdentBytes = new byte[identByteCount];
			this.otpIdentPos = new int[identByteCount][2];
			
			for (int i = 0; i < identByteCount; i++)
			{
				this.otpIdentPos[i][0] = this.rng.nextInt(this.otpBlockCount);
				this.otpIdentPos[i][1] = this.rng.nextInt(this.otpBlockSize);
			}
			
			this.paddParam1 = paddParam1;
			this.paddParam2 = paddParam2;
			this.authMethod = "WeCa";
			this.authLen = authlength;
			this.keyWarnSize = warningSize;
			this.keyWindowSize = windowSize;
			long sosWindowSize = 5 * (this.otpBlockCount * 4 + 33 + this.paddParam1);
			
			this.initialized = true;
			
			this.otpBlocks = new BlockAssignList[(KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS | 1) + 1];
			this.otpPlan = new BlockPlan[(KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS | 1) + 1];
			
			this.otpBlocks[KeyRing.BLOCKTYPE_E | 0] = new BlockAssignList(this.otpBlocks);
			this.otpBlocks[KeyRing.BLOCKTYPE_A | 0] = new BlockAssignList(this.otpBlocks);
			this.otpBlocks[KeyRing.BLOCKTYPE_E | 1] = new BlockAssignList(this.otpBlocks);
			this.otpBlocks[KeyRing.BLOCKTYPE_A | 1] = new BlockAssignList(this.otpBlocks);
			this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 0] = new BlockAssignList(this.otpBlocks);
			this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 0] = new BlockAssignList(this.otpBlocks);
			this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 1] = new BlockAssignList(this.otpBlocks);
			this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 1] = new BlockAssignList(this.otpBlocks);
			
			this.otpPlan[KeyRing.BLOCKTYPE_E | 0] = new BlockPlan(this.otpBlocks[KeyRing.BLOCKTYPE_E | 0]);
			this.otpPlan[KeyRing.BLOCKTYPE_A | 0] = new BlockPlan(this.otpBlocks[KeyRing.BLOCKTYPE_A | 0]);
			this.otpPlan[KeyRing.BLOCKTYPE_E | 1] = new BlockPlan(this.otpBlocks[KeyRing.BLOCKTYPE_E | 1]);
			this.otpPlan[KeyRing.BLOCKTYPE_A | 1] = new BlockPlan(this.otpBlocks[KeyRing.BLOCKTYPE_A | 1]);
			this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 0] = new BlockPlan(
					this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 0]);
			this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 0] = new BlockPlan(
					this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 0]);
			this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 1] = new BlockPlan(
					this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 1]);
			this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 1] = new BlockPlan(
					this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 1]);
			
			this.fillPlan(this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 0], 0, sosWindowSize);
			this.fillPlan(this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 0], 0, sosWindowSize);
			this.fillPlan(this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 1], 1, sosWindowSize);
			this.fillPlan(this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 1], 1, sosWindowSize);
			this.fillPlan(this.otpPlan[KeyRing.BLOCKTYPE_E | 0], 1, this.keyWindowSize);
			this.fillPlan(this.otpPlan[KeyRing.BLOCKTYPE_A | 0], 1, this.keyWindowSize);
			this.fillPlan(this.otpPlan[KeyRing.BLOCKTYPE_E | 1], 0, this.keyWindowSize);
			this.fillPlan(this.otpPlan[KeyRing.BLOCKTYPE_A | 1], 0, this.keyWindowSize);
			
			this.lastAction = System.currentTimeMillis();
			
			this.keyKnownMsgs = new KnownMsgs(new byte[0], new byte[0], this.otpBlocks);
			
			this.dirty = true;
			
		}
		catch (RngResponse e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (FileNotFoundException e)
		{
			throw new KeyringResponse(4, e);
		}
		catch (UiResponse e)
		{
			throw new KeyringResponse(0, e);
		}
	}
	
	public void loadExternalKeyData(String filename) throws KeyringResponse
	{
		if (this.initialized)
			throw new KeyringResponse(0);
		
		try
		{
			if (this.cacheSettings == null)
				this.readCache();
			
			if (this.ringId == null)
			{
				String rid = this.cacheSettings.getValueString(null, "defaultKeyRing");
				if (rid != null)
					this.ringId = ByteArray.fromHex(rid);
			}
			
			if (this.ringId == null)
			{
				this.ringId = this.rng.next(4);
				this.cacheSettings.setValue(null, "defaultKeyRing", ByteArray.toHex(this.ringId));
			}
			
			File sf = new File(filename);
			if (!sf.exists())
			{
				this.ui.warningMessage("Import key file " + sf.getAbsolutePath() + " not found.");
				throw new KeyringResponse(2);
			}
			
			this.ringFile = new RandomAccessFile(sf, "rwd");
			this.importing = true;
			this.readSettings();
			this.importing = false;
			this.ringFile.close();
			
			this.participant = this.keyOwner;
			
			this.otpFile = new File(sf.getParent() + File.separator + this.otpPath);
			if (!this.otpFile.exists())
			{
				this.ui.warningMessage("Import pad file " + this.otpFile.getAbsolutePath() + " not found.");
				throw new KeyringResponse(7);
			}
			
			this.initialized = true;
		}
		catch (RngResponse e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (FileNotFoundException e)
		{
			throw new KeyringResponse(2, e);
		}
		catch (IOException e)
		{
			throw new KeyringResponse(2, e);
		}
	}
	
	public void importKeyData() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		try
		{
			if (this.cacheSettings == null)
				this.readCache();
			
			if (this.ringId == null && !this.createNewRing)
			{
				String rid = this.cacheSettings.getValueString(null, "defaultKeyRing");
				if (rid != null)
					this.ringId = ByteArray.fromHex(rid);
			}
			
			if (this.ringId == null || this.createNewRing)
			{
				this.ringId = this.rng.next(4);
				this.cacheSettings.setValue(null, "defaultKeyRing", ByteArray.toHex(this.ringId));
			}
			
			String hexring = ByteArray.toHex(this.ringId);
			
			File sf = this.getRingFile();
			if (!this.createNewRing && sf.exists() && sf.length() > 0)
			{
				// load existing ring
				try
				{
					this.ringFile = new RandomAccessFile(sf, "rwd");
					this.generatedOrImported = true;
					this.readSettings();
				}
				catch (KeyringResponse e)
				{
					if (e.getErrorCode() != 1)
						throw e;
				}
			}
			else
			{
				ui.message("Creating new key ring: " + hexring);
				// create ring
				this.cacheSettings.setValue(null, "defaultKeyRing", ByteArray.toHex(this.ringId));
				
				this.ringFile = new RandomAccessFile(sf, "rwd");
				this.ringSettings = new IniFileParser();
				this.ringSettings.setValue(null, "keyRingId", hexring);
				this.rng.next(this.ringSalt);
				byte[] pw = this.ui.getNewPassphrase(hexring);
				if (pw.length < 3)
					throw new KeyringResponse(8);
				byte[] keys = this.pwdToKey(pw, 48);
				
				this.ringKey = new SecretKeySpec(keys, 0, 16, "AES");
				this.ringIv = new IvParameterSpec(keys, 16, 16);
			}
			if (!sf.canWrite())
				throw new KeyringResponse(4);
			
			this.ui.message("Importing key: " + ByteArray.toHex(this.keyId));
			
			this.updateLastAction();
			
			if (this.otpPathOverwrite != null) // specific override
			{
				this.otpPath = this.otpPathOverwrite;
				this.otpPathOverwrite = null;
			}
			else
				this.otpPath = ByteArray.toHex(this.keyId) + ".pad";
			
			if (this.basePath == null || this.otpPath.contains(File.separator))
				this.otpFile = new File(this.otpPath);
			else
				this.otpFile = new File(this.basePath + File.separator + this.otpPath);
			
			this.otpKey = this.rng.next(16);
			this.otpIv = this.rng.next(16);
			this.dirty = true;
			
			if (this.otpFile.exists())
			{
				this.ui.warningMessage("Pad file " + this.otpFile.getAbsolutePath() + " already exists.");
				throw new KeyringResponse(4);
			}
			if (this.otpFile.canWrite())
			{
				this.ui.warningMessage("Pad file " + this.otpFile.getAbsolutePath() + " cannot be written.");
				throw new KeyringResponse(4);
			}
		}
		catch (FileNotFoundException e)
		{
			throw new KeyringResponse(2, e);
		}
		catch (RngResponse e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (UiResponse e)
		{
			throw new KeyringResponse(0, e);
		}
		
	}
	
	public void exportKeyData(String newdir) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		String hexkey = ByteArray.toHex(this.keyId);
		
		File dir = new File(newdir);
		if (!dir.canWrite())
		{
			this.ui.warningMessage("Cannot write to directory " + dir.getAbsolutePath());
			throw new KeyringResponse(4);
		}
		
		File file = new File(dir.getAbsolutePath() + File.separator + hexkey + ".key");
		if (file.canRead())
		{
			this.ui.warningMessage("Target file already exists " + file.getAbsolutePath());
			throw new KeyringResponse(4);
		}
		
		try
		{
			this.ringFile = new RandomAccessFile(file, "rwd");
			// ui.verboseMessage("writing new key info to: " +
			// file.getAbsolutePath());
			
			ui.message("Please enter a temporary passphrase to protect the exported key files.");
			byte[] pw = this.ui.getNewPassphrase(hexkey);
			if (pw.length < 3)
				throw new KeyringResponse(8);
			byte[] keys = this.pwdToKey(pw, 48);
			
			this.ringKey = new SecretKeySpec(keys, 0, 16, "AES");
			this.ringIv = new IvParameterSpec(keys, 16, 16);
			
			this.participant = 1 - this.participant;
			this.keyOwner = this.participant;
			
			this.otpKey = this.rng.next(16);
			this.otpIv = this.rng.next(16);
			this.otpPath = hexkey + ".pad";
			this.otpFile = new File(dir.getAbsolutePath() + File.separator + hexkey + ".pad");
			
			this.dirty = true;
			this.exported = true;
			ui.message("Writing key settings...");
			this.storeSettings(true);
		}
		catch (FileNotFoundException e)
		{
			throw new KeyringResponse(1, e);
		}
		catch (RngResponse e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (UiResponse e)
		{
			throw new KeyringResponse(0, e);
		}
		
	}
	
	public void changePwd() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		try
		{
			byte[] pwd = this.ui.getNewPassphrase(ByteArray.toHex(this.ringId));
			if (pwd.length < 3)
				throw new KeyringResponse(8);
			
			byte[] keys;
			
			this.rng.next(this.ringSalt);
			keys = this.pwdToKey(pwd, 32);
			
			this.ringKey = new SecretKeySpec(keys, 0, 16, "AES");
			this.ringIv = new IvParameterSpec(keys, 16, 16);
			this.dirty = true;
		}
		catch (RngResponse e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (KeyringResponse e)
		{
			throw e;
		}
		catch (UiResponse e)
		{
			throw new KeyringResponse(0, e);
		}
	}
	
	public void keyChangeAlias(String alias) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		this.keyAlias = alias;
		this.dirty = true;
	}
	
	@Override
	public boolean keyInSync() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		return !this.keyOutOfSync;
	}
	
	@Override
	public void keySetSync(boolean inSync) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		this.keyOutOfSync = !inSync;
		
		if (!inSync)
		{
			// deactivate all keys in ring
			for (String k : this.ringSettings.getSections())
			{
				if (k != "")
				{
					this.ringSettings.setValue(k, "keyOutOfSync", true);
				}
			}
			this.forceupdate = true;
		}
		
		this.dirty = true;
		
	}
	
	@Override
	public BlockPlan[] keyGetPartnerSync() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		return this.partnerPlan;
	}
	
	@Override
	public void keySetPartnerSync(BlockPlan[] partnerPlans) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		if (partnerPlans == null)
			this.partnerPlan = new BlockPlan[(KeyRing.BLOCKTYPE_A | 1) + 1];
		else
			this.partnerPlan = partnerPlans;
		
		this.dirty = true;
		this.forceupdate = true;
	}
	
	@Override
	public BlockPlan getCurrentPlan(int participant, int type) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		int part = participant;
		if (part == KeyRing.PARTICIP_ME)
			part = this.participant;
		else if (part == KeyRing.PARTICIP_OTHER)
			part = 1 - this.participant;
		
		return this.otpPlan[part | type].clone();
	}
	
	@Override
	public BlockPlan importPlan(int participant, int type, byte[] init) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		int part = participant;
		if (part == KeyRing.PARTICIP_ME)
			part = this.keyOwner;
		else if (part == KeyRing.PARTICIP_OTHER)
			part = 1 - this.keyOwner;
		
		try
		{
			BlockPlan np = new BlockPlan(init, this.otpBlocks[part | type]);
			return np;
		}
		catch (IllegalArgumentException e)
		{
			throw new KeyringResponse(9, e);
		}
		catch (IllegalStateException e)
		{
			throw new KeyringResponse(10, e);
		}
	}
	
	@Override
	public void addBlocks(int participant, int type, byte[] blocks, int startPos) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		int part = participant;
		if (part == KeyRing.PARTICIP_ME)
			part = this.keyOwner;
		else if (part == KeyRing.PARTICIP_OTHER)
			part = 1 - this.keyOwner;
		
		byte[] n = new byte[4];
		System.arraycopy(blocks, startPos, n, 0, 4);
		int blockid = ByteArray.toInt(n);
		if (blockid < 0)
			blockid = -blockid - 1;
		
		BlockAssignList bal = this.otpBlocks[type | part];
		int blockPos = bal.blockPos(blockid);
		
		if (blockPos == -1)
		{
			// blockPos = bal.size();
			throw new KeyringResponse(9);
		}
		int numblocks = (blocks.length - startPos) / 4;
		int checkblocks = Math.min(bal.size() - blockPos, numblocks);
		
		int i = 1;
		int added = 0;
		
		for (; i < checkblocks; i++)
		{
			System.arraycopy(blocks, 4 * i + startPos, n, 0, 4);
			blockid = ByteArray.toInt(n);
			if (blockid < 0)
				blockid = -blockid - 1;
			
			if (bal.getBlock(blockPos + i) != blockid)
			{
				this.ui.warningMessage("Could not add blocks. Previous block missmatch: " + bal.getBlock(blockPos + i) +
						" != " + blockid);
				throw new KeyringResponse(9);
			}
		}
		
		for (; i < numblocks; i++)
		{
			try
			{
				System.arraycopy(blocks, 4 * i + startPos, n, 0, 4);
				blockid = ByteArray.toInt(n);
				if (blockid < 0)
					blockid = -blockid - 1;
				
				if (blockid >= this.otpBlockCount)
				{
					this.ui.warningMessage("Could not add blocks. Invalid BlockId: " + blockid);
					throw new KeyringResponse(9);
				}
				
				bal.addBlock(blockid);
				added++;
			}
			catch (IllegalStateException e)
			{
				this.ui.warningMessage("Duplicate block detected");
			}
		}
		
		if (added > 0)
			this.dirty = true;
	}
	
	@Override
	public void updatePlan(int participant, int type, BlockPlan plan) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		int part = participant;
		if (part == KeyRing.PARTICIP_ME)
			part = this.keyOwner;
		else if (part == KeyRing.PARTICIP_OTHER)
			part = 1 - this.keyOwner;
		
		try
		{
			if (plan.greaterThan(this.otpPlan[part | type]))
			{
				this.otpPlan[part | type] = plan;
				this.dirty = true;
			}
		}
		catch (IllegalArgumentException e)
		{
			throw new KeyringResponse(9, e);
		}
		catch (IllegalStateException e)
		{
			throw new KeyringResponse(9, e);
		}
	}
	
	@Override
	public void fastForwardPlan(BlockPlan plan, long forward) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		BlockData b = this.getBlockData(plan.getBlockId());
		int pointer = plan.getPointer();
		
		try
		{
			while (forward > 0)
			{
				int space = b.calculateSize() - pointer;
				int move = (int) Math.min(forward, space);
				pointer += move;
				forward -= move;
				if (forward > 0)
				{
					b = this.getBlockData(plan.nextBlock());
					pointer = 0;
				}
			}
		}
		catch (NoSuchElementException e)
		{
			throw new KeyringResponse(9, e);
		}
		plan.setPointer(pointer);
	}
	
	@Override
	public void fillPlan(BlockPlan plan) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		this.fillPlan(plan, this.keyOwner, this.keyWindowSize);
	}
	
	private void fillPlan(BlockPlan plan, int blocksFromParticip, long size) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		try
		{
			while (this.remainingBytes(plan) < size)
			{
				plan.addBlock(this.getNextFreeBlock(blocksFromParticip));
				this.dirty = true;
			}
		}
		catch (KeyringResponse r)
		{
			this.ui.warningMessage("Could not extend OTP Window: No more unused blocks!");
			return;
		}
		catch (IllegalArgumentException e)
		{
			throw new KeyringResponse(9, e);
		}
		catch (IllegalStateException e)
		{
			throw new KeyringResponse(9, e);
		}
	}
	
	private int getNextFreeBlock(int blocksFromParticip) throws KeyringResponse
	{
		// pick first (part = 0) or last (1) block
		// -1 for part = 0, count for 1
		int pick = blocksFromParticip * (this.otpBlockCount + 1) - 1;
		
		boolean used;
		
		do
		{
			pick = pick + 1 - 2 * blocksFromParticip; // inc for part = 0, dec for 1
			used = false;
			
			for (int i = 0; i < this.otpBlocks.length && !used; i++)
				if (this.otpBlocks[i].containsBlock(pick))
					used = true;
		}
		while (used);
		
		if (pick >= this.otpBlockCount || pick < 0)
			throw new KeyringResponse(9);
		return pick;
		
	}
	
	public BlockData getBlockData(int blockId)
	{
		if (this.blockDataCache.containsKey(blockId))
			return this.blockDataCache.get(blockId);
		else
		{
			int startAddress = blockId * this.otpBlockSize;
			
			List<Integer> blocks = new LinkedList<Integer>();
			for (int i = 0; i < this.otpIdentBytes.length; i++)
				if (this.otpIdentPos[i][0] == blockId)
					blocks.add(this.otpIdentPos[i][1]);
			
			int[] identPos = new int[blocks.size()];
			for (int i = 0; i < blocks.size(); i++)
				identPos[i] = blocks.get(i);
			
			BlockData bd = new BlockData(blockId, startAddress, this.otpBlockSize, identPos);
			this.blockDataCache.put(blockId, bd);
			return bd;
		}
	}
	
	public int getMaxBlockSize() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		return this.otpBlockSize;
	}
	
	public int getBlockCount() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		return this.otpBlockCount;
	}
	
	@Override
	public long remainingBytes(BlockPlan plan)
	{
		int[] bl = plan.getBlocks();
		if (bl.length == 0)
			return 0;
		
		int rb = this.getBlockData(bl[0]).calculateSize() - plan.getPointer();
		
		for (int i = 1; i < bl.length; i++)
			rb += this.getBlockData(bl[i]).calculateSize();
		
		return rb;
	}
	
	@Override
	public byte[] getKeyId() throws KeyringResponse
	{
		if (this.keyId == null)
			throw new KeyringResponse(0);
		return this.keyId;
	}
	
	@Override
	public int getKeyOwner() throws KeyringResponse
	{
		if (this.keyId == null)
			throw new KeyringResponse(0);
		return this.keyOwner;
	}
	
	/**
	 * Returns the size of the OTP
	 * 
	 * @return OTP size in byte
	 * @throws KeyringResponse
	 */
	public long getOtpSize() throws KeyringResponse
	{
		if (this.keyId == null)
			throw new KeyringResponse(0);
		return this.otpBlockCount * this.otpBlockSize;
	}
	
	@Override
	public int getPaddingParam1() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		return this.paddParam1;
	}
	
	@Override
	public int getPaddingParam2() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		return this.paddParam2;
	}
	
	@Override
	public int getAuthLength() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		return this.authLen;
	}
	
	@Override
	public boolean[] verifyMessage(byte[] hash, BlockPlan eStart, BlockPlan eEnd, BlockPlan aStart, BlockPlan aEnd)
			throws KeyringResponse
	{
		try
		{
			boolean[] res = this.keyKnownMsgs.isLegit(hash, eStart, eEnd, aStart, aEnd);
			this.dirty = this.dirty || res[1];
			return res;
		}
		catch (IllegalArgumentException e)
		{
			throw new KeyringResponse(0, e);
		}
	}
	
	/**
	 * Returns the key for decrypting the corresponding pad file
	 * 
	 * @return The OTP key as AES SecretKeySpec
	 * @throws KeyringResponse
	 */
	public byte[] getOtpKey() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		return this.otpKey;
	}
	
	public byte[] getOtpIv() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		return this.otpIv;
	}
	
	public byte[] getIdentBytes() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		return this.otpIdentBytes;
	}
	
	public void updateIdentBytes(byte[] newIdent) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		if (this.otpIdentBytes.length != newIdent.length)
			throw new KeyringResponse(0);
		
		this.otpIdentBytes = newIdent;
		this.dirty = true;
	}
	
	public int[][] getIdentPos() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		return this.otpIdentPos;
	}
	
	/**
	 * Returns the file handle for the corresponding pad file
	 * 
	 * @return The pad file handle
	 * @throws KeyringResponse
	 */
	public File getOtpFile() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		return this.otpFile;
	}
	
	public void setDefaultKeyRing() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		this.cacheSettings.setValue(null, "defaultKeyRing", ByteArray.toHex(this.ringId));
	}
	
	public void displayKeyInfo() throws KeyringResponse
	{
		this.ui.message("Key ID: " + ByteArray.toHex(this.keyId));
		this.ui.message("Key alias: " + this.keyAlias);
		this.ui.message("Ring ID: " + ByteArray.toHex(this.ringId));
		this.ui.message("Key owner: " + this.keyOwner + (this.keyOwner == 0 ? " (key created here)" : " (imported key)"));
		this.ui.message("OTP file path: " + this.otpPath);
		this.ui.message("Last used at: " + DateFormat.getDateInstance(DateFormat.MEDIUM).format(new Date(this.lastAction)));
		if (this.keyOutOfSync)
			this.ui.message("\nKey is temporarily deactivated, because it has been found out of sync!\n");
		
		this.ui.message("OTP total size: " + (this.otpBlockSize * this.otpBlockCount / (1024 * 1024)) + " MByte");
		this.ui.verboseMessage(" (" + (this.otpBlockSize * this.otpBlockCount) + " byte)");
		
		this.ui.message("OTP block size: " + (this.otpBlockSize / 1024) + " kByte");
		this.ui.verboseMessage(" (" + (this.otpBlockSize) + " byte)");
		
		this.ui.message("Window size: " + (this.keyWindowSize / 1024) + " kByte");
		this.ui.verboseMessage(" (" + (this.keyWindowSize) + " byte)");
		
		this.ui.verboseMessage("Authentication method: " + this.authMethod);
		this.ui.verboseMessage("Authentication length: " + this.authLen + " byte");
		this.ui.verboseMessage("Message padding median: " + this.paddParam1);
		this.ui.verboseMessage("Message padding distribution: " + this.paddParam2);
		this.ui.message("");
		
		// CALCULATE USAGE %
		this.ui.message("Current remaining OTP capacity");
		long enc = this.remainingBytes(this.otpPlan[KeyRing.BLOCKTYPE_E | this.keyOwner]);
		long auth = this.remainingBytes(this.otpPlan[KeyRing.BLOCKTYPE_A | this.keyOwner]);
		long freespace = this.getOtpSize();
		for (BlockAssignList bal : this.otpBlocks)
		{
			freespace -= bal.size() * this.otpBlockSize;
		}
		
		this.ui.message("Encryption:     " + (enc / 1024) + " kByte");
		this.ui.verboseMessage(" (" + enc + " byte)");
		this.ui.message("Authentication: " + (enc / 1024) + " kByte");
		this.ui.verboseMessage(" (" + auth + " byte)");
		
		this.ui.message("Unassociated OTP capacity: " + (freespace / 1024) + " kByte (" +
				Math.round((double) freespace / this.getOtpSize() * 10000) / 100 + "%)");
		this.ui.verboseMessage(" (" + freespace + " byte)");
		
		this.ui.verboseMessage("");
		this.ui.verboseMessage("Current block usage:");
		this.ui.verboseMessage(" BlockList 0 E: " + this.otpBlocks[KeyRing.BLOCKTYPE_E | 0]);
		this.ui.verboseMessage(" BlockList 0 A: " + this.otpBlocks[KeyRing.BLOCKTYPE_A | 0]);
		this.ui.verboseMessage(" BlockList 1 E: " + this.otpBlocks[KeyRing.BLOCKTYPE_E | 1]);
		this.ui.verboseMessage(" BlockList 1 A: " + this.otpBlocks[KeyRing.BLOCKTYPE_A | 1]);
		
		this.ui.verboseMessage("");
		this.ui.verboseMessage(" CurrentPos 0 E: " + this.otpPlan[KeyRing.BLOCKTYPE_E | 0]);
		this.ui.verboseMessage(" CurrentPos 0 A: " + this.otpPlan[KeyRing.BLOCKTYPE_A | 0]);
		this.ui.verboseMessage(" CurrentPos 1 E: " + this.otpPlan[KeyRing.BLOCKTYPE_E | 1]);
		this.ui.verboseMessage(" CurrentPos 1 A: " + this.otpPlan[KeyRing.BLOCKTYPE_A | 1]);
		
		// this.ui.verboseMessage("");
		// this.ui.verboseMessage(" BlockList 0 E (sos): " +
		// this.otpBlocks[KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS | 0]);
		// this.ui.verboseMessage(" BlockList 0 A (sos): " +
		// this.otpBlocks[KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS | 0]);
		// this.ui.verboseMessage(" BlockList 1 E (sos): " +
		// this.otpBlocks[KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS | 1]);
		// this.ui.verboseMessage(" BlockList 1 A (sos): " +
		// this.otpBlocks[KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS | 1]);
		//
		this.ui.verboseMessage("");
		this.ui.verboseMessage(" CurrentPos 0 E (sos): " + this.otpPlan[KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS | 0]);
		this.ui.verboseMessage(" CurrentPos 0 A (sos): " + this.otpPlan[KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS | 0]);
		this.ui.verboseMessage(" CurrentPos 1 E (sos): " + this.otpPlan[KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS | 1]);
		this.ui.verboseMessage(" CurrentPos 1 A (sos): " + this.otpPlan[KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS | 1]);
		
		this.ui.verboseMessage("");
		this.ui.verboseMessage("Known message areas: " + this.keyKnownMsgs);
		
	}
	
	public void listInstalledKeys() throws KeyringResponse
	{
		this.ui.verboseMessage("Key ID;Ring ID;Key alias;Window size left");
		
		if (this.cacheSettings == null)
			this.readCache();
		
		int i = 0;
		
		for (String keyId : this.cacheSettings.getSections())
		{
			if (keyId != "")
				this.ui.message(keyId + ";" + this.cacheSettings.getValueString(keyId, "keyRing") + ";" +
						this.cacheSettings.getValueString(keyId, "keyAlias") + ";" +
						this.cacheSettings.getValueString(keyId, "sizeLeft"));
			i++;
		}
		
		if (i == 0)
		{
			ui.warningMessage("No installed keys found.");
		}
	}
	
	@Override
	public KeyringResponse finish(boolean success)
	{
		KeyringResponse res = new KeyringResponse(true);
		
		if (this.initialized)
		{
			
			try
			{
				long freespace = this.getOtpSize();
				for (BlockAssignList bal : this.otpBlocks)
				{
					freespace -= bal.size() * this.otpBlockSize;
				}
				if (freespace < this.keyWarnSize)
					this.ui.warningMessage("Remaining unassociated OTP Capacity: " + (freespace / 1024) + " kByte (" +
							Math.round((double) freespace / this.getOtpSize() * 10000) / 100 + "%)");
			}
			catch (KeyringResponse e)
			{
			}
			
			// save keyring settings
			if (this.dirty && (success || this.forceupdate))
			{
				try
				{
					if (this.otpPathOverwrite != null &&
							this.ui.promptYN("Store otp location " + this.otpPathOverwrite + " for key " +
									ByteArray.toHex(this.keyId) + " permanently?", true))
						this.otpPath = this.otpPathOverwrite;
					// save ringSettings
					this.storeSettings(success);
					this.ringFile.close();
				}
				catch (KeyringResponse e)
				{
					res = e;
				}
				catch (IOException e)
				{
					res = new KeyringResponse(4, e);
				}
				catch (UiResponse e)
				{
					res = new KeyringResponse(0, e);
				}
				this.ui.verboseMessage("Key Ring settings saved.");
			}
			else
				this.ui.verboseMessage("Key Ring settings not " + (this.dirty ? "successfull." : "dirty."));
			
			// update and save cacheSettings
			if (!this.exported)
			{
				try
				{
					String r = ByteArray.toHex(this.ringId);
					if (this.cacheSettings == null)
						this.readCache();
					
					for (String k : this.ringSettings.getSections())
					{
						if (k != "")
						{
							this.cacheSettings.setValue(k, "keyRing", r);
							this.cacheSettings.setValue(k, "keyAlias", this.ringSettings.getValueString(k, "keyAlias"));
						}
					}
					
					BufferedWriter bw = new BufferedWriter(new FileWriter(this.cacheFileName));
					bw.write(this.cacheSettings.export());
					bw.close();
				}
				catch (KeyringResponse e)
				{
					res = e;
				}
				catch (IOException e)
				{
					res = new KeyringResponse(4, e);
				}
			}
			this.ringKey = null;
			this.ringIv = null;
			this.otpKey = null;
			this.otpIv = null;
			
		}
		
		this.initialized = false;
		return res;
	}
	
	private File getRingFile() throws KeyringResponse
	{
		if (this.cacheSettings == null)
			this.readCache();
		
		if (this.ringId == null)
		{
			String rid = this.cacheSettings.getValueString(ByteArray.toHex(this.keyId), "keyRing");
			if (rid != null)
				this.ringId = ByteArray.fromHex(rid);
		}
		
		if (this.ringId == null)
		{
			String rid = this.cacheSettings.getValueString(null, "defaultKeyRing");
			if (rid != null)
				this.ringId = ByteArray.fromHex(rid);
		}
		
		if (this.ringId == null)
			throw new KeyringResponse(1);
		
		String setpath = ByteArray.toHex(this.ringId) + ".set";
		if (this.basePath != null)
			setpath = this.basePath + File.separator + setpath;
		
		return new File(setpath);
	}
	
	private void updateLastAction() throws KeyringResponse
	{
		long currenttime = System.currentTimeMillis();
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		if (currenttime - this.lastAction > this.lastActionWarnThreshold)
		{
			try
			{
				Boolean datecorrect = this.ui.promptYN("This key ring has not been used for a long time. " +
						"If you did not use any of its keys for that long, there is nothing wrong with this. " +
						"But if you did, it might be a sign of unauthorized modification. In this case, " +
						"a resynchronisation should be done.\n\nPlease check carefully, if your last access was on " +
						DateFormat.getDateInstance(DateFormat.MEDIUM).format(new Date(this.lastAction)) +
						".\nIs this date correct? ", true);
				if (!datecorrect)
				{
					this.keySetSync(false);
					this.finish(true);
					this.ui.warningMessage("Key temporarily disabled. Please use the --request-sync parameter "
							+ "to create a syncronisation request.");
					new KeyringResponse(3);
				}
			}
			catch (UiResponse e)
			{
				throw new KeyringResponse(0, e);
			}
		}
		
		this.lastAction = currenttime;
	}
	
	private byte[] pwdToKey(byte[] pwd, int keylen) throws KeyringResponse
	{
		if (this.ringSalt == null)
			throw new KeyringResponse(0);
		if (pwd.length < 3)
			throw new KeyringResponse(6);
		
		try
		{
			int c = 1000;
			Key pw = new SecretKeySpec(pwd, "HmacSHA1");
			
			Mac hash = Mac.getInstance("HmacSHA1");
			hash.init(pw);
			
			int hashlen = hash.getMacLength();
			
			int l = keylen / hashlen;
			if (keylen % hashlen > 0)
				l++;
			
			byte[] key = new byte[keylen];
			for (int t = 0; t < l; t++)
			{
				byte[] tt = new byte[hashlen];
				byte[] ui = new byte[this.ringSalt.length + 4];
				System.arraycopy(this.ringSalt, 0, ui, 0, this.ringSalt.length);
				System.arraycopy(ByteArray.fromInt(t + 1), 0, ui, this.ringSalt.length, 4);
				for (int i = 0; i < c; i++)
				{
					ui = hash.doFinal(ui);
					
					for (int j = 0; j < hashlen; j++)
						tt[j] ^= ui[j];
				}
				int copy = (t < l - 1) ? hashlen : keylen - hashlen * t;
				System.arraycopy(tt, 0, key, t * hashlen, copy);
			}
			return key;
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (InvalidKeyException e)
		{
			throw new KeyringResponse(0, e);
		}
	}
	
	private void readCache() throws KeyringResponse
	{
		if (this.basePath != null && !this.cacheFileName.contains(File.separator))
			this.cacheFileName = this.basePath + File.separator + this.cacheFileName;
		
		BufferedReader br;
		try
		{
			br = new BufferedReader(new FileReader(this.cacheFileName));
			this.cacheSettings = new IniFileParser();
			char[] buf = new char[1024];
			StringBuffer read = new StringBuffer();
			int r = 0;
			while ((r = br.read(buf)) != -1)
			{
				read.append(String.valueOf(buf, 0, r));
			}
			br.close();
			this.cacheSettings.parse(read.toString());
		}
		catch (FileNotFoundException e)
		{
			this.cacheSettings = new IniFileParser();
		}
		catch (ParseException e)
		{
			this.cacheSettings = new IniFileParser();
		}
		catch (IOException e)
		{
			throw new KeyringResponse(0, e);
		}
	}
	
	private void readSettings() throws KeyringResponse
	{
		try
		{
			Cipher ciph = Cipher.getInstance("AES/PCBC/NoPadding");
			
			if (ringFile.length() <= this.ringSalt.length + 2 * ciph.getBlockSize())
				throw new KeyringResponse(3);
			
			this.ringFile.seek(0);
			this.ringFile.read(this.ringSalt);
			
			byte[] pwd;
			if (this.importing)
				pwd = this.ui.getPassphrase("Import");
			else
				pwd = this.ui.getPassphrase(ByteArray.toHex(this.ringId));
			
			byte[] keys;
			
			if (pwd != null)
				keys = this.pwdToKey(pwd, 32);
			else
				throw new KeyringResponse(0);
			
			this.ringKey = new SecretKeySpec(keys, 0, 16, "AES");
			this.ringIv = new IvParameterSpec(keys, 16, 16);
			ciph.init(Cipher.DECRYPT_MODE, this.ringKey, this.ringIv);
			byte[] encrypted = new byte[(int) this.ringFile.length() - this.ringSalt.length];
			this.ringFile.read(encrypted);
			
			byte[] clear = ciph.doFinal(encrypted);
			
			byte[] chcksm = new byte[ciph.getBlockSize()];
			byte[] params = new byte[clear.length - 2 * ciph.getBlockSize()];
			
			System.arraycopy(clear, clear.length - ciph.getBlockSize(), chcksm, 0, ciph.getBlockSize());
			
			// wrong authkey ==> probably invalid passphrase
			if (!Arrays.equals(chcksm, new byte[ciph.getBlockSize()]))
			{
				throw new KeyringResponse(6);
			}
			
			System.arraycopy(clear, ciph.getBlockSize(), params, 0, clear.length - 2 * ciph.getBlockSize());
			
			this.ringSettings = new IniFileParser(new String(params));
			
			if (this.importing)
			{
				String hexkey = this.ringSettings.getValueString(null, "transferKey");
				if (hexkey == null)
				{
					this.ui.warningMessage("No exported key found in specified file.");
					throw new KeyringResponse(3);
				}
				this.keyId = ByteArray.fromHex(hexkey);
			}
			
			String hexkey = ByteArray.toHex(this.keyId);
			
			if (this.generatedOrImported)
			{
				if (this.ringSettings.getSections().contains(hexkey))
				{
					this.ui.warningMessage("Key " + hexkey + " already exists in key ring " + ByteArray.toHex(this.ringId) + ".");
					throw new KeyringResponse(4);
				}
			}
			else
			{
				if (!this.ringSettings.getSections().contains(hexkey))
				{
					this.ui.warningMessage("Key " + hexkey + " not found in key ring " + ByteArray.toHex(this.ringId) + ".");
					throw new KeyringResponse(1);
				}
				
				this.lastAction = this.ringSettings.getValueLong(null, "lastAction");
				
				// read current settings
				this.keyOwner = this.ringSettings.getValueInt(hexkey, "keyOwner");
				this.keyAlias = this.ringSettings.getValueString(hexkey, "keyAlias");
				// this.keyIsValid = this.ringSettings.getValueBool(hexkey,
				// "keyIsValid");
				this.keyOutOfSync = this.ringSettings.getValueBool(hexkey, "keyOutOfSync");
				
				this.otpPath = this.ringSettings.getValueString(hexkey, "otpPath");
				this.otpKey = this.ringSettings.getValueBytes(hexkey, "otpKey");
				this.otpIv = this.ringSettings.getValueBytes(hexkey, "otpIv");
				
				this.otpIdentBytes = this.ringSettings.getValueBytes(hexkey, "otpIdentBytes");
				this.otpIdentPos = new int[this.otpIdentBytes.length][2];
				byte[] ip = this.ringSettings.getValueBytes(hexkey, "otpIdentPos");
				byte[] n = new byte[4];
				
				for (int i = 0; i < this.otpIdentBytes.length; i++)
				{
					System.arraycopy(ip, 8 * i, n, 0, 4);
					this.otpIdentPos[i][0] = ByteArray.toInt(n);
					System.arraycopy(ip, 8 * i + 4, n, 0, 4);
					this.otpIdentPos[i][1] = ByteArray.toInt(n);
				}
				
				this.otpBlockSize = this.ringSettings.getValueInt(hexkey, "otpBlockSize");
				this.otpBlockCount = this.ringSettings.getValueInt(hexkey, "otpBlockCount");
				
				this.paddParam1 = this.ringSettings.getValueInt(hexkey, "paddParam1");
				this.paddParam2 = this.ringSettings.getValueInt(hexkey, "paddParam2");
				this.authMethod = this.ringSettings.getValueString(hexkey, "authMethod");
				this.authLen = this.ringSettings.getValueInt(hexkey, "authLen");
				this.keyWarnSize = this.ringSettings.getValueLong(hexkey, "keyWarnSize");
				this.keyWindowSize = this.ringSettings.getValueLong(hexkey, "keyWindowSize");
				
				this.otpBlocks = new BlockAssignList[(KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS | 1) + 1];
				this.otpBlocks[KeyRing.BLOCKTYPE_E | 0] = new BlockAssignList(this.ringSettings.getValueBytes(hexkey,
						"eBlocks0"), this.otpBlocks);
				this.otpBlocks[KeyRing.BLOCKTYPE_A | 0] = new BlockAssignList(this.ringSettings.getValueBytes(hexkey,
						"aBlocks0"), this.otpBlocks);
				this.otpBlocks[KeyRing.BLOCKTYPE_E | 1] = new BlockAssignList(this.ringSettings.getValueBytes(hexkey,
						"eBlocks1"), this.otpBlocks);
				this.otpBlocks[KeyRing.BLOCKTYPE_A | 1] = new BlockAssignList(this.ringSettings.getValueBytes(hexkey,
						"aBlocks1"), this.otpBlocks);
				this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 0] = new BlockAssignList(
						this.ringSettings.getValueBytes(hexkey, "eSosBlocks0"), this.otpBlocks);
				this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 0] = new BlockAssignList(
						this.ringSettings.getValueBytes(hexkey, "aSosBlocks0"), this.otpBlocks);
				this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 1] = new BlockAssignList(
						this.ringSettings.getValueBytes(hexkey, "eSosBlocks1"), this.otpBlocks);
				this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 1] = new BlockAssignList(
						this.ringSettings.getValueBytes(hexkey, "aSosBlocks1"), this.otpBlocks);
				
				this.otpPlan = new BlockPlan[(KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS | 1) + 1];
				this.otpPlan[KeyRing.BLOCKTYPE_E | 0] = new BlockPlan(this.ringSettings.getValueBytes(hexkey, "ePlan0"),
						this.otpBlocks[KeyRing.BLOCKTYPE_E | 0]);
				this.otpPlan[KeyRing.BLOCKTYPE_A | 0] = new BlockPlan(this.ringSettings.getValueBytes(hexkey, "aPlan0"),
						this.otpBlocks[KeyRing.BLOCKTYPE_A | 0]);
				this.otpPlan[KeyRing.BLOCKTYPE_E | 1] = new BlockPlan(this.ringSettings.getValueBytes(hexkey, "ePlan1"),
						this.otpBlocks[KeyRing.BLOCKTYPE_E | 1]);
				this.otpPlan[KeyRing.BLOCKTYPE_A | 1] = new BlockPlan(this.ringSettings.getValueBytes(hexkey, "aPlan1"),
						this.otpBlocks[KeyRing.BLOCKTYPE_A | 1]);
				this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 0] = new BlockPlan(this.ringSettings.getValueBytes(
						hexkey, "eSosPlan0"), this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 0]);
				this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 0] = new BlockPlan(this.ringSettings.getValueBytes(
						hexkey, "aSosPlan0"), this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 0]);
				this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 1] = new BlockPlan(this.ringSettings.getValueBytes(
						hexkey, "eSosPlan1"), this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 1]);
				this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 1] = new BlockPlan(this.ringSettings.getValueBytes(
						hexkey, "aSosPlan1"), this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 1]);
				
				byte[] readPlan;
				
				readPlan = this.ringSettings.getValueBytes(hexkey, "partnerE0");
				if (readPlan != null && readPlan.length > 1)
					this.partnerPlan[KeyRing.BLOCKTYPE_E | 0] = new BlockPlan(readPlan, this.otpBlocks[KeyRing.BLOCKTYPE_E | 0]);
				readPlan = this.ringSettings.getValueBytes(hexkey, "partnerA0");
				if (readPlan != null && readPlan.length > 1)
					this.partnerPlan[KeyRing.BLOCKTYPE_A | 0] = new BlockPlan(readPlan, this.otpBlocks[KeyRing.BLOCKTYPE_A | 0]);
				readPlan = this.ringSettings.getValueBytes(hexkey, "partnerE1");
				if (readPlan != null && readPlan.length > 1)
					this.partnerPlan[KeyRing.BLOCKTYPE_E | 1] = new BlockPlan(readPlan, this.otpBlocks[KeyRing.BLOCKTYPE_E | 1]);
				readPlan = this.ringSettings.getValueBytes(hexkey, "partnerA1");
				if (readPlan != null && readPlan.length > 1)
					this.partnerPlan[KeyRing.BLOCKTYPE_A | 1] = new BlockPlan(readPlan, this.otpBlocks[KeyRing.BLOCKTYPE_A | 1]);
				
				byte[] hashes = this.ringSettings.getValueBytes(hexkey, "knownHashes");
				byte[] areas = this.ringSettings.getValueBytes(hexkey, "knownAreas");
				
				this.keyKnownMsgs = new KnownMsgs(hashes, areas, this.otpBlocks);
			}
			
		}
		catch (IOException e)
		{
			throw new KeyringResponse(4, e);
		}
		catch (IllegalBlockSizeException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (BadPaddingException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (InvalidKeyException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (InvalidAlgorithmParameterException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (NoSuchPaddingException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (ParseException e)
		{
			throw new KeyringResponse(3, e);
		}
		catch (IllegalArgumentException e)
		{
			throw new KeyringResponse(9, e);
		}
		catch (IllegalStateException e)
		{
			throw new KeyringResponse(9, e);
		}
		catch (UiResponse e)
		{
			throw new KeyringResponse(0, e);
		}
	}
	
	private void storeSettings(boolean success) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		String hexkey = ByteArray.toHex(this.keyId);
		IniFileParser set;
		
		if (this.exported)
		{
			set = new IniFileParser();
			set.setValue(null, "transferKey", hexkey);
			set.setValue(null, "exportDate", System.currentTimeMillis());
		}
		else
			set = this.ringSettings;
		
		// copy all values back
		try
		{
			
			set.setValue(null, "lastAction", this.lastAction);
			
			set.setValue(hexkey, "keyOwner", this.keyOwner);
			set.setValue(hexkey, "keyAlias", this.keyAlias);
			// set.setValue(hexkey, "keyIsValid", this.keyIsValid);
			set.setValue(hexkey, "keyOutOfSync", this.keyOutOfSync);
			
			set.setValue(hexkey, "otpPath", this.otpPath);
			set.setValue(hexkey, "otpKey", this.otpKey);
			set.setValue(hexkey, "otpIv", this.otpIv);
			
			set.setValue(hexkey, "otpIdentBytes", this.otpIdentBytes);
			
			ByteArrayBuilder bab = new ByteArrayBuilder();
			for (int i = 0; i < this.otpIdentBytes.length; i++)
			{
				bab.addAll(ByteArray.fromInt(this.otpIdentPos[i][0]));
				bab.addAll(ByteArray.fromInt(this.otpIdentPos[i][1]));
			}
			
			set.setValue(hexkey, "otpIdentPos", bab.toArray());
			
			set.setValue(hexkey, "otpBlockSize", this.otpBlockSize);
			set.setValue(hexkey, "otpBlockCount", this.otpBlockCount);
			
			set.setValue(hexkey, "paddParam1", this.paddParam1);
			set.setValue(hexkey, "paddParam2", this.paddParam2);
			set.setValue(hexkey, "authMethod", this.authMethod);
			set.setValue(hexkey, "authLen", this.authLen);
			set.setValue(hexkey, "keyWarnSize", this.keyWarnSize);
			set.setValue(hexkey, "keyWindowSize", this.keyWindowSize);
			
			// if (success)
			// {
			set.setValue(hexkey, "eBlocks0", this.otpBlocks[KeyRing.BLOCKTYPE_E | 0].exportList());
			set.setValue(hexkey, "aBlocks0", this.otpBlocks[KeyRing.BLOCKTYPE_A | 0].exportList());
			set.setValue(hexkey, "eBlocks1", this.otpBlocks[KeyRing.BLOCKTYPE_E | 1].exportList());
			set.setValue(hexkey, "aBlocks1", this.otpBlocks[KeyRing.BLOCKTYPE_A | 1].exportList());
			set.setValue(hexkey, "eSosBlocks0", this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 0].exportList());
			set.setValue(hexkey, "aSosBlocks0", this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 0].exportList());
			set.setValue(hexkey, "eSosBlocks1", this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 1].exportList());
			set.setValue(hexkey, "aSosBlocks1", this.otpBlocks[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 1].exportList());
			
			set.setValue(hexkey, "ePlan0", this.otpPlan[KeyRing.BLOCKTYPE_E | 0].exportPlanShort());
			set.setValue(hexkey, "aPlan0", this.otpPlan[KeyRing.BLOCKTYPE_A | 0].exportPlanShort());
			set.setValue(hexkey, "ePlan1", this.otpPlan[KeyRing.BLOCKTYPE_E | 1].exportPlanShort());
			set.setValue(hexkey, "aPlan1", this.otpPlan[KeyRing.BLOCKTYPE_A | 1].exportPlanShort());
			set.setValue(hexkey, "eSosPlan0", this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 0].exportPlanShort());
			set.setValue(hexkey, "aSosPlan0", this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 0].exportPlanShort());
			set.setValue(hexkey, "eSosPlan1", this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_E | 1].exportPlanShort());
			set.setValue(hexkey, "aSosPlan1", this.otpPlan[KeyRing.BLOCKTYPE_SOS | KeyRing.BLOCKTYPE_A | 1].exportPlanShort());
			
			set.setValue(hexkey, "knownHashes", this.keyKnownMsgs.exportHashes());
			set.setValue(hexkey, "knownAreas", this.keyKnownMsgs.exportAreas());
			// }
			
			set.setValue(hexkey, "partnerE0", this.partnerPlan[KeyRing.BLOCKTYPE_E | 0] == null ? new byte[0]
					: this.partnerPlan[KeyRing.BLOCKTYPE_E | 0].exportPlanShort());
			set.setValue(hexkey, "partnerA0", this.partnerPlan[KeyRing.BLOCKTYPE_A | 0] == null ? new byte[0]
					: this.partnerPlan[KeyRing.BLOCKTYPE_A | 0].exportPlanShort());
			set.setValue(hexkey, "partnerE1", this.partnerPlan[KeyRing.BLOCKTYPE_E | 1] == null ? new byte[0]
					: this.partnerPlan[KeyRing.BLOCKTYPE_E | 1].exportPlanShort());
			set.setValue(hexkey, "partnerA1", this.partnerPlan[KeyRing.BLOCKTYPE_A | 1] == null ? new byte[0]
					: this.partnerPlan[KeyRing.BLOCKTYPE_A | 1].exportPlanShort());
			
			Cipher ciph = Cipher.getInstance("AES/PCBC/NoPadding");
			ciph.init(Cipher.ENCRYPT_MODE, this.ringKey, this.ringIv);
			
			byte[] data = set.export().getBytes("utf8");
			int padding = ciph.getBlockSize() - (data.length % ciph.getBlockSize());
			
			byte[] random = this.rng.next(ciph.getBlockSize());
			
			byte[] clear = new byte[random.length + data.length + padding + ciph.getBlockSize()];
			
			System.arraycopy(random, 0, clear, 0, random.length);
			System.arraycopy(data, 0, clear, random.length, data.length);
			
			byte[] encrypted = ciph.doFinal(clear);
			
			this.ringFile.seek(0);
			this.ringFile.setLength(0);
			this.ringFile.write(this.ringSalt);
			this.ringFile.write(encrypted);
		}
		catch (RngResponse e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (NoSuchPaddingException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (InvalidKeyException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (InvalidAlgorithmParameterException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (UnsupportedEncodingException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (IllegalBlockSizeException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (BadPaddingException e)
		{
			throw new KeyringResponse(0, e);
		}
		catch (IOException e)
		{
			throw new KeyringResponse(4, e);
		}
		catch (IllegalStateException e)
		{
			throw new KeyringResponse(0, e);
		}
		this.dirty = false;
	}
	
}
