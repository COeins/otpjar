package otp.helpr;

public class BlockData
{
	private int blockId;
	private long startAddress;
	private int length;
	private int[] skipBytes;
	
	public BlockData(int blockId, long startAddress, int length, int[] skipBytes)
	{
		this.blockId = blockId;
		this.startAddress = startAddress;
		this.length = length;
		this.skipBytes = skipBytes;
	}
	
	/**
	 * Returns the id of the block
	 * 
	 * @return
	 */
	public int getBlockId()
	{
		return blockId;
	}
	
	/**
	 * Returns the start address of the block
	 * 
	 * @return
	 */
	public long getStartAddress()
	{
		return startAddress;
	}
	
	/**
	 * Returns the byte length of the block
	 * 
	 * @return
	 */
	public int getLength()
	{
		return length;
	}
	
	/**
	 * Returns the positions of skip bytes in the block
	 * 
	 * @return
	 */
	public int[] getSkipBytes()
	{
		return skipBytes;
	}
	
	/**
	 * Returns the useable size of the block
	 * 
	 * @return
	 */
	public int calculateSize()
	{
		return this.length - this.skipBytes.length;
	}
}
