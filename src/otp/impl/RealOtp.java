package otp.impl;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import otp.Otp;
import otp.Rng;
import otp.UserInterface;
import otp.helpr.BlockPlan;
import otp.helpr.ByteArray;
import otp.response.KeyringResponse;
import otp.response.OtpResponse;
import otp.response.RngResponse;

/**
 * Otp module that uses a AES encrypted local file otp
 */
public class RealOtp extends Otp
{
	private final String padCipher = "AES/ECB/NoPadding";
	
	private RealKeyRing ring;
	private Rng rng;
	private UserInterface ui;
	
	private RandomAccessFile file;
	private static List<String> verifiedFiles;
	
	private Cipher[] ciphA = new Cipher[3];
	private Cipher[] ciphB = new Cipher[3];
	
	private static final int CIPH_ENC = 0;
	private static final int CIPH_DEC = 1;
	private static final int CIPH_NEW = 2;
	
	private boolean initialized = false;
	private boolean writeable = false;
	
	private BlockPlan plan;
	
	private int outerSize;
	private int outerBlock = -1;
	private int[] outerSkips;
	
	private int innerSize;
	private int innerPerOuter;
	
	private int oBlock = -1;
	private int iBlock = -1;
	private byte[] iBytes = null;
	
	private int[] deltaId = new int[] { -1, -1, -1 };
	private byte[][] delta = new byte[][] { null, null, null };
	
	private boolean dirty = false;
	
	/**
	 * Creates new RealOtp, for encryption and decryption
	 * 
	 * @param ring
	 * Corresponding KeySettings module
	 * @param ui
	 * UserInterface for status messages
	 */
	public RealOtp(RealKeyRing ring, UserInterface ui)
	{
		this.ring = ring;
		this.ui = ui;
	}
	
	/**
	 * Creates new RealOtp, for key generation
	 * 
	 * @param ring
	 * Corresponging KeySettings module
	 * @param rng
	 * Rng module for OTP generation
	 * @param ui
	 * UserInterface for status messages
	 */
	public RealOtp(RealKeyRing ring, Rng rng, UserInterface ui)
	{
		this.ring = ring;
		this.rng = rng;
		this.ui = ui;
	}
	
	@Override
	public void initialize() throws OtpResponse
	{
		if (!this.initialized)
		{
			try
			{
				// load stuff
				File f = this.ring.getOtpFile();
				if (!f.exists())
					throw new OtpResponse(4);
				
				this.file = new RandomAccessFile(f, "r");
				
				this.ciphA[CIPH_ENC] = Cipher.getInstance(this.padCipher);
				this.ciphA[CIPH_DEC] = this.ciphA[CIPH_ENC];
				this.ciphB[CIPH_ENC] = Cipher.getInstance(this.padCipher);
				this.ciphB[CIPH_DEC] = Cipher.getInstance(this.padCipher);
				
				byte[] keyA = this.ring.getOtpKey();
				byte[] keyB = this.ring.getOtpIv();
				Key keySpecA = new SecretKeySpec(keyA, "AES");
				Key keySpecB = new SecretKeySpec(keyB, "AES");
				
				this.ciphA[CIPH_ENC].init(Cipher.ENCRYPT_MODE, keySpecA);
				this.ciphB[CIPH_ENC].init(Cipher.ENCRYPT_MODE, keySpecB);
				this.ciphB[CIPH_DEC].init(Cipher.DECRYPT_MODE, keySpecB);
				
				this.outerSize = this.ring.getMaxBlockSize();
				this.innerSize = this.ciphB[CIPH_ENC].getBlockSize();
				if (this.outerSize % this.innerSize > 0)
					throw new OtpResponse(0);
				
				this.innerPerOuter = this.outerSize / this.innerSize;
				
				// verify
				String hexkey = ByteArray.toHex(this.ring.getKeyId());
				if (RealOtp.verifiedFiles == null)
					RealOtp.verifiedFiles = new LinkedList<String>();
				
				if (!RealOtp.verifiedFiles.contains(hexkey + ";" + f.getCanonicalPath()))
				{
					if (this.ring.getOtpSize() != this.file.length())
						throw new OtpResponse(1);
					
					byte[] verifyBytes = this.ring.getIdentBytes();
					int[][] verifyPos = this.ring.getIdentPos();
					byte[] check = new byte[1];
					int read;
					
					for (int i = 0; i < verifyBytes.length; i++)
					{
						read = this.readInner(verifyPos[i][0], verifyPos[i][1], check, 0, 1);
						if (read < 1 || check[0] != verifyBytes[i])
						{
							System.out.println(i + ": " + check[0] + " != " + verifyBytes[i]);
							throw new OtpResponse(1);
						}
					}
					
					RealOtp.verifiedFiles.add(hexkey + ";" + f.getCanonicalPath());
				}
				
				this.initialized = true;
			}
			catch (FileNotFoundException e)
			{
				throw new OtpResponse(1, e);
			}
			catch (KeyringResponse e)
			{
				throw new OtpResponse(0, e);
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new OtpResponse(0, e);
			}
			catch (NoSuchPaddingException e)
			{
				throw new OtpResponse(0, e);
			}
			catch (IOException e)
			{
				throw new OtpResponse(1, e);
			}
			catch (InvalidKeyException e)
			{
				throw new OtpResponse(0, e);
			}
		}
	}
	
	/**
	 * Creates a new OTP file. To increase unpredictability, the file could be
	 * xor'ed a number of times.
	 * 
	 * @param iterations
	 * The number of passes the file should be xor'ed with new random
	 * numbers
	 * @throws OtpResponse
	 */
	public void createPad(int iterations) throws OtpResponse
	{
		if (this.rng == null)
			throw new OtpResponse(0);
		
		try
		{
			this.ciphA[CIPH_ENC] = Cipher.getInstance(this.padCipher);
			this.ciphA[CIPH_DEC] = this.ciphA[CIPH_ENC];
			this.ciphB[CIPH_ENC] = Cipher.getInstance(this.padCipher);
			this.ciphB[CIPH_DEC] = Cipher.getInstance(this.padCipher);
			
			byte[] keyA = this.ring.getOtpKey();
			byte[] keyB = this.ring.getOtpIv();
			Key keySpecA = new SecretKeySpec(keyA, "AES");
			Key keySpecB = new SecretKeySpec(keyB, "AES");
			
			this.ciphA[CIPH_ENC].init(Cipher.ENCRYPT_MODE, keySpecA);
			this.ciphB[CIPH_ENC].init(Cipher.ENCRYPT_MODE, keySpecB);
			this.ciphB[CIPH_DEC].init(Cipher.DECRYPT_MODE, keySpecB);
			
			this.outerSize = this.ring.getMaxBlockSize();
			this.innerSize = this.ciphB[CIPH_ENC].getBlockSize();
			
			this.innerPerOuter = this.outerSize / this.innerSize;
			long size = this.ring.getOtpSize();
			
			long innerBlocksTotal = size / this.innerSize;
			if (this.outerSize % this.innerSize > 0)
			{
				this.ui.verboseMessage("Invalid block size: " + this.outerSize);
				throw new OtpResponse(0);
			}
			
			this.file = new RandomAccessFile(this.ring.getOtpFile(), "rw");
			
			byte[] block = new byte[this.innerSize];
			byte[] oldblock = new byte[this.innerSize];
			
			this.ui.initializeProgress(innerBlocksTotal * iterations);
			for (int iteration = 0; iteration < iterations; iteration++)
			{
				for (long i = 0; i < innerBlocksTotal; i++)
				{
					this.ui.updateProgress(i + innerBlocksTotal * iteration);
					this.rng.next(block);
					
					if (iteration > 0)
					{
						this.file.seek(i * this.innerSize);
						this.file.read(oldblock);
						block = ByteArray.xor(block, oldblock);
					}
					
					this.file.seek(i * this.innerSize);
					this.file.write(block);
				}
				this.rng.reseed();
			}
			
			int[][] verifyPos = this.ring.getIdentPos();
			byte[] verifyBytes = new byte[verifyPos.length];
			
			for (int i = 0; i < verifyBytes.length; i++)
			{
				this.readInner(verifyPos[i][0], verifyPos[i][1], verifyBytes, i, 1);
			}
			
			this.ring.updateIdentBytes(verifyBytes);
			
			this.ui.finishProgress();
			
			this.initialized = true;
		}
		catch (FileNotFoundException e)
		{
			throw new OtpResponse(3, e);
		}
		catch (KeyringResponse e)
		{
			throw new OtpResponse(0, e);
		}
		catch (IOException e)
		{
			throw new OtpResponse(3, e);
		}
		catch (RngResponse e)
		{
			throw new OtpResponse(0, e);
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new OtpResponse(0, e);
		}
		catch (NoSuchPaddingException e)
		{
			throw new OtpResponse(0, e);
		}
		catch (InvalidKeyException e)
		{
			throw new OtpResponse(0, e);
		}
	}
	
	/**
	 * Re-encodes a OTP file and stores it to a different location. New key and
	 * location are obtained by re-requesting them from the associated KeySettings
	 * object. Needs to be initialized first.
	 * 
	 * @throws OtpResponse
	 */
	public void reencrypt() throws OtpResponse
	{
		if (!this.initialized)
			throw new OtpResponse(0);
		
		try
		{
			this.ciphA[CIPH_NEW] = Cipher.getInstance(this.padCipher);
			this.ciphB[CIPH_NEW] = Cipher.getInstance(this.padCipher);
			
			byte[] newKeyA = this.ring.getOtpKey();
			byte[] newKeyB = this.ring.getOtpIv();
			Key newKeySpecA = new SecretKeySpec(newKeyA, "AES");
			Key newKeySpecB = new SecretKeySpec(newKeyB, "AES");
			
			this.ciphA[CIPH_NEW].init(Cipher.ENCRYPT_MODE, newKeySpecA);
			this.ciphB[CIPH_NEW].init(Cipher.ENCRYPT_MODE, newKeySpecB);
			
			File newFileName = this.ring.getOtpFile();
			ui.verboseMessage("writing new OTP: " + newFileName.getAbsolutePath());
			
			RandomAccessFile oldFile = this.file;
			RandomAccessFile newFile = new RandomAccessFile(newFileName, "rw");
			
			byte[] oldEnc = new byte[this.innerSize];
			byte[] newEnc = new byte[this.innerSize];
			byte[] plainBl = new byte[this.innerSize];
			
			oldFile.seek(0);
			newFile.seek(0);
			
			ui.initializeProgress(oldFile.length() / this.innerSize);
			
			int outerBlocks = (int) (oldFile.length() / this.outerSize);
			for (int ob = 0; ob < outerBlocks; ob++)
				for (int ib = 0; ib < this.innerPerOuter; ib++)
				{
					ui.updateProgress(ob * this.innerPerOuter + ib);
					oldFile.read(oldEnc);
					this.cryptBlock(oldEnc, plainBl, ob, ib, CIPH_DEC);
					this.cryptBlock(plainBl, newEnc, ob, ib, CIPH_NEW);
					newFile.write(newEnc);
				}
			ui.finishProgress();
			
			newFile.close();
		}
		catch (KeyringResponse e)
		{
			throw new OtpResponse(0, e);
		}
		catch (NoSuchAlgorithmException e)
		{
			throw new OtpResponse(0, e);
		}
		catch (NoSuchPaddingException e)
		{
			throw new OtpResponse(0, e);
		}
		catch (InvalidKeyException e)
		{
			throw new OtpResponse(0, e);
		}
		catch (FileNotFoundException e)
		{
			throw new OtpResponse(1, e);
		}
		catch (IOException e)
		{
			throw new OtpResponse(1, e);
		}
	}
	
	@Override
	public byte next() throws OtpResponse
	{
		byte[] out = new byte[1];
		this.next(out);
		return out[0];
	}
	
	@Override
	public byte[] next(int count) throws OtpResponse
	{
		byte[] out = new byte[count];
		this.next(out);
		return out;
	}
	
	@Override
	public void next(byte[] b) throws OtpResponse
	{
		this.rwOuter(b, false);
	}
	
	@Override
	public void writeNext(byte[] b) throws OtpResponse
	{
		this.rwOuter(b, true);
	}
	
	@Override
	public BlockPlan getPosition() throws OtpResponse
	{
		return this.plan;
	}
	
	@Override
	public void setPosition(BlockPlan plan) throws OtpResponse
	{
		this.plan = plan;
	}
	
	@Override
	public OtpResponse finish(boolean success)
	{
		if (!this.initialized)
			return new OtpResponse(true);
		
		try
		{
			this.initialized = false;
			if (this.dirty)
				this.saveBlock();
			
			this.ciphA[CIPH_DEC] = null;
			this.ciphA[CIPH_ENC] = null;
			this.ciphA[CIPH_NEW] = null;
			this.ciphB[CIPH_DEC] = null;
			this.ciphB[CIPH_ENC] = null;
			this.ciphB[CIPH_NEW] = null;
			
			this.file.close();
		}
		catch (OtpResponse e1)
		{
			return e1;
		}
		catch (IOException e)
		{
			return new OtpResponse(1, e);
		}
		return new OtpResponse(true);
	}
	
	private void rwOuter(byte[] b, boolean write) throws OtpResponse
	{
		if (!this.initialized)
			throw new OtpResponse(0);
		
		int copied = 0;
		
		int currentBlock = this.plan.getBlockId();
		int pos = this.plan.getPointer();
		int oldskip = 0;
		if (this.outerBlock != currentBlock)
		{
			this.outerBlock = currentBlock;
			this.outerSkips = this.ring.getBlockData(currentBlock).getSkipBytes();
		}
		
		while (copied < b.length)
		{
			if (pos >= this.outerSize - this.outerSkips.length)
			{
				try
				{
					currentBlock = this.plan.nextBlock();
					pos = 0;
					oldskip = 0;
					this.outerBlock = currentBlock;
					this.outerSkips = this.ring.getBlockData(currentBlock).getSkipBytes();
				}
				catch (NoSuchElementException e)
				{
					throw new OtpResponse(5, e);
				}
			}
			
			int skip = 0;
			int stop = this.outerSize;
			for (int i = 0; i < this.outerSkips.length; i++)
			{
				if (this.outerSkips[i] <= (pos + Math.max(skip, oldskip)))
					skip++;
				else
					stop = Math.min(stop, this.outerSkips[i]);
			}
			
			int len = Math.min(stop - (pos + skip), b.length - copied);
			
			if (len > 0)
			{
				if (write)
					this.writeInner(this.outerBlock, pos + skip, b, copied, len);
				else
					this.readInner(this.outerBlock, pos + skip, b, copied, len);
				
				copied += len;
				pos += len;
			}
			oldskip = skip;
		}
		
		this.plan.setPointer(pos);
	}
	
	private int readInner(int outerBlock, int absPos, byte[] buffer, int bufferStart, int len) throws OtpResponse
	{
		int toRead = Math.min(len, buffer.length - bufferStart);
		toRead = Math.min(toRead, this.outerSize - absPos);
		int read = 0;
		while (read < toRead)
		{
			int iBlock = (absPos + read) / this.innerSize;
			int iPos = (absPos + read) % this.innerSize;
			this.loadBlock(outerBlock, iBlock);
			int iRead = Math.min(toRead - read, this.innerSize - iPos);
			
			System.arraycopy(this.iBytes, iPos, buffer, bufferStart + read, iRead);
			read += iRead;
		}
		return read;
	}
	
	private int writeInner(int outerBlock, int absPos, byte[] buffer, int bufferStart, int len) throws OtpResponse
	{
		int toWrite = Math.min(len, buffer.length - bufferStart);
		toWrite = Math.min(toWrite, this.outerSize - absPos);
		int written = 0;
		while (written < toWrite)
		{
			int iBlock = (absPos + written) / this.innerSize;
			int iPos = (absPos + written) % this.innerSize;
			this.loadBlock(outerBlock, iBlock);
			int iRead = Math.min(toWrite - written, this.innerSize - iPos);
			System.arraycopy(buffer, bufferStart + written, this.iBytes, iPos, iRead);
			this.dirty = true;
			written += iRead;
		}
		return written;
	}
	
	private void loadBlock(int oBlock, int iBlock) throws OtpResponse
	{
		
		if (this.oBlock == oBlock && this.iBlock == iBlock)
			return;
		
		if (this.dirty)
			this.saveBlock();
		
		if (this.iBytes == null)
			this.iBytes = new byte[this.innerSize];
		
		try
		{
			byte[] read = new byte[this.innerSize];
			this.file.seek((oBlock * this.innerPerOuter + iBlock) * this.innerSize);
			this.file.read(read, 0, this.innerSize);
			
			this.cryptBlock(read, this.iBytes, oBlock, iBlock, CIPH_DEC);
			
			this.oBlock = oBlock;
			this.iBlock = iBlock;
		}
		catch (IOException e)
		{
			ui.warningMessage("Loading failed. oBlock: " + oBlock + ", iBlock: " + iBlock);
			throw new OtpResponse(1, e);
		}
	}
	
	private void saveBlock() throws OtpResponse
	{
		if (!this.writeable)
		{
			try
			{
				this.file = new RandomAccessFile(this.ring.getOtpFile(), "rw");
				this.writeable = true;
			}
			catch (IOException e)
			{
				throw new OtpResponse(1, e);
			}
			catch (KeyringResponse e)
			{
				throw new OtpResponse(0, e);
			}
		}
		
		try
		{
			byte[] write = new byte[this.innerSize];
			this.cryptBlock(this.iBytes, write, this.oBlock, this.iBlock, CIPH_ENC);
			
			this.file.seek((oBlock * this.innerPerOuter + iBlock) * this.innerSize);
			this.file.write(write, 0, this.innerSize);
			this.dirty = false;
		}
		catch (IOException e)
		{
			throw new OtpResponse(1, e);
		}
		
	}
	
	void cryptBlock(byte[] input, byte[] output, int outerId, int innerId, int mode) throws OtpResponse
	{
		try
		{
			if (this.deltaId[mode] != outerId)
			{
				byte[] ctrP = new byte[this.innerSize];
				System.arraycopy(ByteArray.fromLong(outerId), 0, ctrP, 0, 8);
				this.delta[mode] = this.ciphA[mode].doFinal(ctrP);
				this.deltaId[mode] = outerId;
			}
			
			byte[] ctrE = this.mult(this.delta[mode], innerId);
			byte[] loadP = ByteArray.xor(input, ctrE);
			byte[] loadE = this.ciphB[mode].doFinal(loadP);
			
			ByteArray.xor(loadE, ctrE, output);
		}
		catch (IllegalBlockSizeException e)
		{
			throw new OtpResponse(0, e);
		}
		catch (BadPaddingException e)
		{
			throw new OtpResponse(0, e);
		}
	}
	
	/**
	 * Calculates a * 2^b
	 */
	byte[] mult(byte[] a, int b)
	{
		byte[] x = a.clone();
		for (int i = 0; i < b; i++)
		{
			byte ov = 0;
			for (int j = x.length - 1; j >= 0; j--)
			{
				byte ovn = (byte) (x[j] >>> 7 & 1);
				x[j] = (byte) (x[j] << 1 | ov);
				ov = ovn;
			}
			if (ov != 0)
				x[x.length - 1] = (byte) (x[x.length - 1] ^ 0x87);
		}
		
		return a;
	}
}
