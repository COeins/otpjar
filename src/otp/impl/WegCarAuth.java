package otp.impl;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import otp.Authenticator;
import otp.KeyRing;
import otp.Otp;
import otp.helpr.ByteArray;
import otp.response.AuthResponse;
import otp.response.KeyringResponse;
import otp.response.OtpResponse;

/**
 * Authentication module that uses Wegman/Carter type authentication
 */
public class WegCarAuth extends Authenticator
{
	private int authLength; // in bytes
	private int fieldSize; // in bytes
	private byte[] neutral;
	
	private byte[] collector;
	private int collected;
	
	private List<byte[]> stack;
	private long counter;
	
	private Otp otp;
	private KeyRing set;
	private BigInteger p;
	private List<BigInteger> keya;
	private List<BigInteger> keyb;
	
	private boolean initialized = false;
	
	/**
	 * Creates new WegCarAuth
	 * 
	 * @param set
	 * KeySettings module for the Key to be used
	 * @param otp
	 * Otp module set to authentication position
	 */
	public WegCarAuth(KeyRing set, Otp otp)
	{
		this.otp = otp;
		this.set = set;
	}
	
	@Override
	public int setInputSize(long size) throws AuthResponse
	{
		if (this.initialized || this.set == null)
			throw new AuthResponse(0);
		
		long inputSize = size + 1;
		
		try
		{
			this.authLength = set.getAuthLength();
		}
		catch (KeyringResponse e1)
		{
			throw new AuthResponse(0, e1);
		}
		
		this.fieldSize = (int) Math.ceil(this.authLength +
				(Math.log((Math.log(inputSize * 8) / Math.log(2))) / Math.log(2)) / 8);
		
		return (int) Math.ceil(Math.log(inputSize / ((double) this.fieldSize)) / Math.log(2)) * this.fieldSize * 4;
		
	}
	
	@Override
	public void initialize() throws AuthResponse
	{
		if (this.fieldSize == 0)
			throw new AuthResponse(0);
		
		this.neutral = new byte[this.fieldSize];
		this.collector = new byte[this.fieldSize];
		
		this.keya = new LinkedList<BigInteger>();
		this.keyb = new LinkedList<BigInteger>();
		
		this.collected = 0;
		
		this.stack = new LinkedList<byte[]>();
		this.counter = 0;
		
		byte[] p0 = new byte[2 * this.fieldSize + 2];
		p0[0] = 0; // sign bit
		p0[1] = 1; // 2 ^ (2*field-size) + 1
		this.p = new BigInteger(p0).nextProbablePrime();
		
		this.initialized = true;
	}
	
	public int sum = 0;
	
	@Override
	public void next(byte e) throws AuthResponse
	{
		if (!this.initialized)
			throw new AuthResponse(0);
		
		this.sum++;
		
		this.collector[this.collected] = e;
		this.collected++;
		if (this.collected == this.fieldSize)
		{
			this.counter++;
			this.put_stack(this.collector.clone(), 0, 2);
			this.collected = 0;
		}
		
	}
	
	@Override
	public byte[] doFinal() throws AuthResponse
	{
		if (!this.initialized)
			throw new AuthResponse(0);
		
		this.next((byte) 255);
		while (this.collected > 0)
			this.next((byte) 0);
		
		byte[] res = this.calculateMac(null, 0, 2);
		
		if (res == null)
			throw new AuthResponse(0);
		
		byte[] mac = new byte[this.authLength];
		System.arraycopy(res, res.length - this.authLength, mac, 0, this.authLength);
		
		return mac;
	}
	
	@Override
	public int getMacLength() throws AuthResponse
	{
		if (!this.initialized)
			throw new AuthResponse(0);
		
		return this.authLength;
	}
	
	@Override
	public AuthResponse finish(boolean success)
	{
		if (this.initialized)
		{
			this.keya = null;
			this.keyb = null;
			this.initialized = false;
		}
		
		return new AuthResponse(true);
	}
	
	private byte[] combine(byte[] x1, byte[] x2, int layer) throws AuthResponse
	{
		if (this.keya.size() <= layer)
		{
			try
			{
				this.keya.add(layer, ByteArray.toUnsignedBigInt(this.otp.next(2 * this.fieldSize)));
				this.keyb.add(layer, ByteArray.toUnsignedBigInt(this.otp.next(2 * this.fieldSize)));
			}
			catch (OtpResponse e)
			{
				throw new AuthResponse(1, e);
			}
			
		}
		
		// y = (a + b * concat(x1, x2)) mod p
		
		byte[] x = new byte[2 * this.fieldSize];
		
		System.arraycopy(x1, 0, x, 0, this.fieldSize);
		System.arraycopy(x2, 0, x, this.fieldSize, this.fieldSize);
		
		BigInteger numberX = ByteArray.toUnsignedBigInt(x);
		BigInteger numberY = keya.get(layer).add(keyb.get(layer).multiply(numberX)).mod(p);
		
		byte[] y = numberY.toByteArray();
		
		byte[] out = new byte[this.fieldSize];
		int length = this.fieldSize;
		int start = y.length - this.fieldSize;
		
		if (y.length < this.fieldSize)
		{
			start = 0;
			length = y.length;
			for (int i = 0; i < this.fieldSize - y.length; i++)
			{
				out[i] = 0;
			}
		}
		System.arraycopy(y, start, out, this.fieldSize - length, length);
		return out;
	}
	
	private void put_stack(byte[] i, int layer, int poweroftwo) throws AuthResponse
	{
		if (this.counter % poweroftwo == 0)
		{ // get from stack
			byte[] j = this.stack.get(layer);
			this.put_stack(combine(j, i, layer), layer + 1, poweroftwo * 2);
		}
		else
		{ // put into stack
			if (this.stack.size() <= layer)
				this.stack.add(this.neutral);
			this.stack.set(layer, i);
		}
	}
	
	private byte[] calculateMac(byte[] i, int layer, int poweroftwo) throws AuthResponse
	{
		if (layer >= this.stack.size())
			return i;
		
		if (this.counter % poweroftwo >= poweroftwo / 2)
		{ // dirty information present
			byte[] j = this.stack.get(layer);
			
			if (i == null)
				if (layer >= this.stack.size() - 1 && layer > 0)
					return j;
				else
					return this.calculateMac(this.combine(j, this.neutral, layer), layer + 1, poweroftwo * 2);
			else
				return this.calculateMac(this.combine(j, i, layer), layer + 1, poweroftwo * 2);
		}
		else
		{ // no dirt present
			if (i == null)
				return this.calculateMac(i, layer + 1, poweroftwo * 2);
			else
				return this.calculateMac(this.combine(i, this.neutral, layer), layer + 1, poweroftwo * 2);
		}
	}
}
