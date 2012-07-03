package otp.helpr;

import java.math.BigInteger;

public class ByteArray
{
	private final static String radix = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	private final static String hex = "0123456789abcdef";
	
	/**
	 * Class is not to be instantiated
	 */
	private ByteArray()
	{
	}
	
	/**
	 * Converts a bytearray into a string in Radix64 format, inserting linebreaks
	 * every 64 characters
	 * 
	 * @param b
	 * The input bytearray
	 * @return A Radix64 formated string
	 */
	public static String toRadix64(byte[] b)
	{
		return toRadix64(b, 64);
	}
	
	/**
	 * Converts a bytearray into a string in Radix64 format, allowing variable
	 * line length
	 * 
	 * @param b
	 * The input bytearray
	 * @param line_length
	 * The number of characters after which a linebreak is inserted. May
	 * be 0 for no linebreak.
	 * @return A Radix64 formated string
	 */
	public static String toRadix64(byte[] b, int line_length)
	{
		StringBuilder s = new StringBuilder();
		int inx;
		int c = 0;
		int line = 0;
		for (int x = 0; x < b.length; x += 3)
		{
			if (b.length < x + 3)
				c = x + 3 - b.length;
			
			inx = (b[x] & 0xff) << 16;
			if (c < 2)
				inx |= (b[x + 1] & 0xff) << 8;
			if (c < 1)
				inx |= (b[x + 2] & 0xff);
			
			line = (line_length > 0) ? (line + 4) % line_length : -1;
			
			s.append(radix.charAt(inx >>> 18 & 0x3F));
			if (line == 3)
				s.append("\r\n");
			s.append(radix.charAt(inx >>> 12 & 0x3F));
			if (line == 2)
				s.append("\r\n");
			s.append(c < 2 ? radix.charAt(inx >>> 6 & 0x3F) : "=");
			if (line == 1)
				s.append("\r\n");
			s.append(c < 1 ? radix.charAt(inx & 0x3F) : "=");
			if (line == 0 && x + 3 < b.length)
				s.append("\r\n");
		}
		return s.toString();
	}
	
	/**
	 * Generates a bytearray from a Radix64 formated string
	 * 
	 * @param s
	 * Input in Radix64 format. May contain [a-zA-Z0-9+/=], whitespaces
	 * and linebreaks will be skipped.
	 * @return bytearray
	 */
	public static byte[] fromRadix64(String s)
	{
		ByteArrayBuilder b = new ByteArrayBuilder();
		int col = 0;
		int end = 4;
		byte[] buffer = new byte[4];
		for (int i = 0; i < s.length(); i++)
		{
			char t = s.charAt(i);
			
			if (t == '=' && end == 4)
				end = col;
			
			if (t == '\r' || t == '\n' || t == ' ')
			{
				
			}
			else
			{
				buffer[col++] = (byte) t;
				
				if (col == 4)
				{
					col = 0;
					int inx;
					inx = (radix.indexOf(buffer[0]) & 0x3f) << 18;
					inx |= (radix.indexOf(buffer[1]) & 0x3f) << 12;
					if (end > 2)
						inx |= (radix.indexOf(buffer[2]) & 0x3f) << 6;
					if (end > 3)
						inx |= radix.indexOf(buffer[3]);
					
					b.add((byte) (inx >>> 16 & 0xff));
					if (end > 2)
						b.add((byte) (inx >>> 8 & 0xff));
					if (end > 3)
						b.add((byte) (inx & 0xff));
				}
			}
		}
		
		return b.toArray();
	}
	
	/**
	 * Converts a bytearray into a string using the hexadecimal format.
	 * 
	 * @param b
	 * The input bytearray
	 * @return A hexadecimal formated string
	 */
	public static String toHex(byte[] b)
	{
		StringBuilder out = new StringBuilder();
		
		for (int i = 0; i < b.length; i++)
		{
			out.append(hex.charAt((b[i] & 0xF0) >> 4)).append(hex.charAt(b[i] & 0x0F));
		}
		return out.toString();
	}
	
	/**
	 * Converts a bytearray into a string using the hexadecimal format, inserting
	 * a delimiter after each 2 byte
	 * 
	 * @param b
	 * The input bytearray
	 * @param delimiter
	 * A string to be inserted after each byte
	 * @return A hexadecimal formated string
	 */
	public static String toHex(byte[] b, String delimiter)
	{
		StringBuilder out = new StringBuilder();
		
		for (int i = 0; i < b.length; i++)
		{
			out.append(hex.charAt((b[i] & 0xF0) >> 4)).append(hex.charAt(b[i] & 0x0F)).append(delimiter);
		}
		return out.toString();
	}
	
	/**
	 * Converts a hexadecimal formated string into a bytearray
	 * 
	 * @param h
	 * Input in hexadecimal format. May contain [0-9a-fA-F]
	 * @return
	 * @throws NumberFormatException
	 */
	public static byte[] fromHex(String h) throws NumberFormatException
	{
		h = h.trim();
		int max = (int) Math.ceil((double) h.length() / 2);
		byte[] b = new byte[max];
		int off = 0;
		for (int x = 0; x < max; x++)
		{
			int i;
			if (x == 0 && h.length() % 2 > 0)
			{
				i = Integer.parseInt(h.substring(0, 1) + "", 16);
				// complete 2s compliment
				if (i >= 8)
					i += 240;
				off = -1;
			}
			else
			{
				i = Integer.parseInt(h.substring(2 * x + off, 2 * x + 2 + off), 16);
			}
			b[x] = (byte) i;
		}
		
		return b;
	}
	
	/**
	 * Converts a bytearray to a long value. First bit is treated as sign bit.
	 * 
	 * @param b
	 * bytearray to be converted
	 * @return The resulting long value
	 */
	public static long toLong(byte[] b)
	{
		int off = b.length - 1;
		int max = b.length < 8 ? b.length : 8;
		long l = 0;
		for (int x = 0; x < max; x++)
			l |= ((long) b[off - x] & 0xff) << (8 * x);
		
		return l;
	}
	
	/**
	 * Converts a long value to a byte array
	 * 
	 * @param l
	 * The input value
	 * @return The resulting bytearray
	 */
	public static byte[] fromLong(long l)
	{
		byte[] b = new byte[8];
		for (int x = 0; x < 8; x++)
			b[7 - x] = (byte) (l >>> (8 * x));
		return b;
	}
	
	/**
	 * Converts a bytearray to a int value. First bit is treated as sign bit.
	 * 
	 * @param b
	 * bytearray to be converted
	 * @return The resulting int value
	 */
	public static int toInt(byte[] b)
	{
		int off = b.length - 1;
		int max = b.length < 4 ? b.length : 4;
		int i = 0;
		for (int x = 0; x < max; x++)
			i |= (b[off - x] & 0xff) << (8 * x);
		return i;
	}
	
	/**
	 * Converts a int value to a byte array
	 * 
	 * @param l
	 * The input value
	 * @return The resulting bytearray
	 */
	public static byte[] fromInt(int i)
	{
		byte[] b = new byte[4];
		for (int x = 0; x < 4; x++)
			b[3 - x] = (byte) (i >>> (8 * x));
		return b;
	}
	
	/**
	 * Converts a bytearray into a BigInteger object. First bit is treated as
	 * value bit, not as sign bit.
	 * 
	 * @param in
	 * bytearray to be converted
	 * @return The resulting BigInteger representation
	 */
	public static BigInteger toUnsignedBigInt(byte[] in)
	{
		byte[] out = new byte[in.length + 1];
		out[0] = 0;
		System.arraycopy(in, 0, out, 1, in.length);
		return new BigInteger(out);
	}
	
	/**
	 * Converts parts of a bytearray into a BigInteger object. If the given array
	 * is larger, the first length - @bytes bytes are ignored. First bit is
	 * treated as value bit, not as sign bit.
	 * 
	 * @param in
	 * bytearray to be converted
	 * @param bytes
	 * number of bytes to be used in the conversion
	 * @return The resulting BigInteger representation
	 */
	public static BigInteger toUnsignedBigInt(byte[] in, int bytes)
	{
		
		byte[] out = new byte[bytes + 1];
		int start = 0;
		int length = bytes;
		
		if (in.length > bytes)
			start = in.length - bytes;
		else if (in.length < bytes)
			length = in.length;
		
		for (int i = 0; i < start; i++)
			out[i] = 0;
		System.arraycopy(in, start, out, bytes - length + 1, length);
		
		return new BigInteger(out);
	}
	
	/**
	 * Calculates a CRC24 checksum of a given bytearray
	 * 
	 * @param in
	 * The input for the checksum calculation
	 * @param iv
	 * The initialization vector for the CRC Operation
	 * @return The calculated checksum
	 */
	public static int crc24(byte[] in, int iv)
	{
		int gen = 0x1864cfb;
		int out = iv;
		
		for (int i = 0; i < in.length; i++)
		{
			out ^= in[i] << 16;
			for (int j = 0; j < 8; j++)
			{
				out <<= 1;
				if ((out & 0x1000000) != 0)
					out ^= gen;
			}
		}
		
		return out;
	}
	
	/**
	 * Calculates the xor representation of every byte in two bytearrays, if the
	 * array sizes don't match, the longer ones rightmost bytes will be copied
	 * unchanged
	 * 
	 * @param in1
	 * Input 1
	 * @param in2
	 * Input 2
	 * @return Input 1 (xor) Input 2
	 */
	public static byte[] xor(byte[] in1, byte[] in2)
	{
		byte[] out = new byte[Math.max(in1.length, in2.length)];
		ByteArray.xor(in1, in2, out);
		return out;
	}
	
	/**
	 * Writes the xor representation of every byte from two bytearrays into a
	 * third array. If the array sizes don't match, output will be filled with the
	 * unchanged rightmost bytes of the longer input array or 0-bytes
	 * 
	 * @param in1
	 * Input 1
	 * @param in2
	 * Input 2
	 * @param out
	 * Output = Input 1 (xor) Input 2
	 */
	public static void xor(byte[] in1, byte[] in2, byte[] out)
	{
		for (int i = 0; i < out.length; i++)
		{
			if (i < in1.length && i < in2.length)
				out[i] = (byte) (in1[i] ^ in2[i]);
			else if (i < in1.length)
				out[i] = in1[i];
			else if (i < in2.length)
				out[i] = in2[i];
			else
				out[i] = 0;
		}
	}
	
}
