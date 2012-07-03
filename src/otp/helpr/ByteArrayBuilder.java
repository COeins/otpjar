package otp.helpr;

import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

public class ByteArrayBuilder
{
	
	private List<byte[]> collector;
	private byte[] current;
	private int collected;
	private final int array_length = 128;
	
	/**
	 * Creates a empty ByteArrayBuilder.
	 */
	public ByteArrayBuilder()
	{
		this.collector = new LinkedList<byte[]>();
		this.current = new byte[this.array_length];
		this.collected = 0;
	}
	
	/**
	 * Adds a new byte to the ByteArrayBuilder
	 * 
	 * @param b
	 * The byte value to be added.
	 * @return Success of the operation.
	 */
	public boolean add(byte b)
	{
		this.current[this.collected++] = b;
		if (this.collected == this.array_length)
		{
			this.collector.add(this.current.clone());
			this.collected = 0;
		}
		return true;
	}
	
	/**
	 * Adds a array of bytes to the ByteArrayBuilder
	 * 
	 * @param b
	 * The bytearray to be added.
	 * @return Success of the operation.
	 */
	public boolean addAll(byte[] b)
	{
		for (byte a : b)
			this.add(a);
		return true;
	}
	
	/**
	 * Empties the ByteArrayBuilder
	 */
	public void clear()
	{
		this.collector.clear();
		this.collected = 0;
	}
	
	/**
	 * Returns the number of bytes in the ByteArrayBuilder
	 * 
	 * @return Current size
	 */
	public int size()
	{
		return this.collector.size() * this.array_length + this.collected;
	}
	
	/**
	 * Converts the ByteArrayBuilder into a bytearray
	 * 
	 * @return The bytearray representation of the ByteArrayBuilder
	 */
	public byte[] toArray()
	{
		byte[] a = new byte[this.size()];
		int j;
		
		Iterator<byte[]> i = this.collector.iterator();
		for (j = 0; i.hasNext(); j++)
			System.arraycopy(i.next(), 0, a, j * this.array_length, this.array_length);
		
		if (this.collected > 0)
			System.arraycopy(this.current, 0, a, j * this.array_length, this.collected);
		
		return a;
	}
	
	@Override
	public String toString()
	{
		return new String(this.toArray());
	}

	public String toString(String charset) throws UnsupportedEncodingException
	{
		return new String(this.toArray(), charset);
	}
}
