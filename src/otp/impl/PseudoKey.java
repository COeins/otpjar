package otp.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import otp.KeyRing;
import otp.helpr.BlockPlan;
import otp.helpr.ByteArray;
import otp.response.KeyringResponse;

/**
 * KeySettings module for use with PseudoOTP. This module is just for testing
 * purposes and should not be used in a real application.
 */

// TODO rework class
public class PseudoKey extends KeyRing
{
	private boolean initialized = false;
	private int key_id = -1;
	private int direction;
	File filename = null;
	FileInputStream finput = null;
	FileOutputStream foutput = null;
	
	private byte[][] seed = new byte[2][8];
	private int[] position = new int[2];
	private int minpadding;
	private int maxpadding;
	
	/**
	 * Creates new PseudoKey for encryption
	 * 
	 * @param key_id
	 * The key to be used
	 * @param participant
	 * The participant to be used
	 */
	public PseudoKey(int key_id, int participant)
	{
		this.key_id = key_id;
		this.direction = participant;
	}
	
	/**
	 * Creates new PseudoKey for decryption
	 */
	public PseudoKey()
	{
	}
	
	@Override
	public void selectKey(byte[] keyid, int participant) throws KeyringResponse
	{
		this.key_id = ByteArray.toInt(keyid);
		this.direction = participant;
	}
	
	@Override
	public void initialize() throws KeyringResponse
	{
		
		this.filename = new File(this.key_id + ".set");
		
		if (this.key_id == -1 || this.direction < 0 || this.direction > 1)
			throw new KeyringResponse(1);
		
		try
		{
			this.finput = new FileInputStream(this.filename);
			
			byte[] b = new byte[4];
			
			this.finput.read(b, 0, 4);
			int key_id = ByteArray.toInt(b);
			if (key_id != this.key_id)
				throw new KeyringResponse(3);
			
			this.finput.read(this.seed[0], 0, 8);
			this.finput.read(this.seed[1], 0, 8);
			
			this.finput.read(b, 0, 4);
			this.position[0] = ByteArray.toInt(b);
			
			this.finput.read(b, 0, 4);
			this.position[1] = ByteArray.toInt(b);
			
			this.finput.read(b, 0, 4);
			this.minpadding = ByteArray.toInt(b);
			
			this.finput.read(b, 0, 4);
			this.maxpadding = ByteArray.toInt(b);
			
			this.initialized = true;
		}
		catch (FileNotFoundException e)
		{
			throw new KeyringResponse(1, e);
		}
		catch (IOException e)
		{
			throw new KeyringResponse(2, e);
		}
		
	}
	
	/**
	 * Returns the current position of the selected participant
	 * 
	 * @return current position
	 * @throws KeyringResponse
	 */
	public int get_position() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		return this.position[this.direction];
	}
	
	/**
	 * Updates the position of the selected participant if nessessary
	 * 
	 * @param new_pos
	 * New position of selected participant
	 * @throws KeyringResponse
	 */
	public void set_position(int new_pos) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		if (this.position[this.direction] < new_pos)
			this.position[this.direction] = new_pos;
	}
	
	@Override
	public byte[] getKeyId()
	{
		// return this.key_id;
		return null;
	}
	
	@Override
	public int getKeyOwner()
	{
		return this.direction;
	}
	
	/**
	 * Returns the seed for the pseudo OTP of the selected participant
	 * 
	 * @return seed
	 * @throws KeyringResponse
	 */
	public byte[] getseed() throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		return this.seed[this.direction];
	}
	
	/**
	 * Changes the seed for the selected participant
	 * 
	 * @param seed
	 * the new seed
	 * @throws KeyringResponse
	 */
	public void setseed(byte[] seed) throws KeyringResponse
	{
		if (!this.initialized)
			throw new KeyringResponse(0);
		
		this.seed[this.direction] = seed;
	}
	
	@Override
	public KeyringResponse finish(boolean success)
	{
		if (this.initialized)
		{
			try
			{
				if (this.finput != null)
					this.finput.close();
				this.foutput = new FileOutputStream(this.filename);
				
				this.foutput.write(ByteArray.fromInt(this.key_id));
				this.foutput.write(this.seed[0]);
				this.foutput.write(this.seed[1]);
				this.foutput.write(ByteArray.fromInt(this.position[0]));
				this.foutput.write(ByteArray.fromInt(this.position[1]));
				this.foutput.write(ByteArray.fromInt(this.minpadding));
				this.foutput.write(ByteArray.fromInt(this.maxpadding));
				
				this.foutput.close();
				return new KeyringResponse(true);
			}
			catch (IOException e)
			{
				return new KeyringResponse(4, e);
			}
		}
		else
			return new KeyringResponse(true);
		
	}
	
	@Override
	public int getPaddingParam1()
	{
		return this.minpadding;
	}
	
	@Override
	public int getPaddingParam2()
	{
		return this.maxpadding;
	}
	
	/**
	 * @throws KeyringResponse
	 */
	public void createKey(long size, long warningsize, int minpadding, int maxpadding, int authlength)
			throws KeyringResponse
	{
		this.seed[0] = new byte[] { 01, 23, 45, 67, 89, 101, 112, -125 };
		this.seed[1] = new byte[] { -125, 112, 101, 89, 67, 45, 23, 01 };
		this.position[0] = 0;
		this.position[1] = 0;
		this.minpadding = minpadding;
		this.maxpadding = maxpadding;
		this.initialized = true;
		return;
	}
	
	@Override
	public int getAuthLength()
	{
		return 16;
	}
	
	@Override
	public BlockPlan getCurrentPlan(int participant, int type) throws KeyringResponse
	{
		// TODO Auto-generated method stub
		return null;
	}
	
	@Override
	public BlockPlan importPlan(int participant, int type, byte[] init) throws KeyringResponse
	{
		// TODO Auto-generated method stub
		return null;
	}
	
	@Override
	public void updatePlan(int participant, int type, BlockPlan plan) throws KeyringResponse
	{
		// TODO Auto-generated method stub
		
	}
	
	@Override
	public void fastForwardPlan(BlockPlan plan, long bytes) throws KeyringResponse
	{
		// TODO Auto-generated method stub
		
	}
	
	@Override
	public void fillPlan(BlockPlan plan) throws KeyringResponse
	{
		// TODO Auto-generated method stub
		
	}
	
	@Override
	public boolean verifyMessage(byte[] hash, BlockPlan eStart, BlockPlan eEnd, BlockPlan aStart, BlockPlan aEnd)
			throws KeyringResponse
	{
		// TODO Auto-generated method stub
		return false;
	}
	
	@Override
	public long remainingBytes(BlockPlan enc_pos)
	{
		// TODO Auto-generated method stub
		return 0;
	}
	
	@Override
	public void addBlocks(int participant, int type, byte[] blocks, int startPos) throws KeyringResponse
	{
		// TODO Auto-generated method stub
		
	}
	
}
