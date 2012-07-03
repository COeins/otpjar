package otp.helpr;

import java.util.NoSuchElementException;

public class BlockPlan implements Comparable<BlockPlan>
{
	
	private int pointer;
	private BlockAssignList blocks;
	private int blockPos;
	
	public BlockPlan(BlockAssignList blocks)
	{
		this.pointer = 0;
		this.blockPos = 0;
		this.blocks = blocks;
	}
	
	public BlockPlan(int pointer, int blockId, BlockAssignList blocks)
	{
		this.pointer = pointer;
		this.blocks = blocks;
		this.blockPos = this.blocks.blockPos(blockId);
	}
	
	public BlockPlan(byte[] init, BlockAssignList blocks) throws IllegalArgumentException, IllegalStateException
	{
		
		this.blocks = blocks;
		
		if (init.length < 8)
			throw new IllegalArgumentException("Init bytes incomplete");
		
		byte[] n = new byte[4];
		System.arraycopy(init, 0, n, 0, 4);
		this.pointer = ByteArray.toInt(n);
		
		int fstblock = -1;
		int scan = 0;
		while (fstblock < 0 && scan < init.length - 4)
		{
			scan += 4;
			System.arraycopy(init, scan, n, 0, 4);
			int b = ByteArray.toInt(n);
			if (b < 0)
				fstblock = -b - 1;
		}
		
		this.blockPos = this.blocks.blockPos(fstblock);
		
		if (this.blockPos < 0)
		{
			throw new IllegalStateException("Initialized block does not exist");
		}
	}
	
	/**
	 * Generates a byte array containing current block id and pointer
	 * 
	 * @return
	 * @throws IllegalStateException
	 */
	public byte[] exportPlanShort() throws IllegalStateException
	{
		ByteArrayBuilder out = new ByteArrayBuilder();
		out.addAll(ByteArray.fromInt(this.pointer));
		int a = this.blocks.getBlock(this.blockPos);
		int b = -a - 1;
		out.addAll(ByteArray.fromInt(b));
		return out.toArray();
	}
	
	/**
	 * Generates a byte array containing current block id, pointer and all
	 * following blocks
	 * 
	 * @return
	 * @throws IllegalStateException
	 */
	public byte[] exportPlanComplete() throws IllegalStateException
	{
		ByteArrayBuilder out = new ByteArrayBuilder();
		out.addAll(ByteArray.fromInt(this.pointer));
		
		for (int i = this.blockPos; i < this.blocks.size(); i++)
		{
			int blockId = this.blocks.getBlock(i);
			if (i == this.blockPos)
				blockId = -blockId - 1;
			
			out.addAll(ByteArray.fromInt(blockId));
		}
		
		return out.toArray();
	}
	
	/**
	 * Generates a byte array containing all block ids between a certain position
	 * and the end of the list
	 * 
	 * @param from
	 * @return
	 * @throws IllegalStateException
	 * @throws IllegalArgumentException
	 */
	public byte[] exportPlanBetween(BlockPlan from) throws IllegalStateException, IllegalArgumentException
	{
		ByteArrayBuilder out = new ByteArrayBuilder();
		
		int start = 0;
		if (from != null)
		{
			if (this.blocks != from.blocks)
				throw new IllegalArgumentException("Blocks not comparable");
			start = Math.min(from.blockPos, this.blockPos);
		}
		
		out.addAll(ByteArray.fromInt(this.pointer));
		for (int i = start; i < this.blocks.size(); i++)
		{
			int blockId = this.blocks.getBlock(i);
			if (i == this.blockPos)
			{
				blockId = -blockId - 1;
			}
			out.addAll(ByteArray.fromInt(blockId));
		}
		
		return out.toArray();
	}
	
	/**
	 * Returns the current position
	 * 
	 * @return
	 */
	public int getPointer()
	{
		return pointer;
	}
	
	/**
	 * Sets the current position
	 * 
	 * @param pointer
	 */
	public void setPointer(int pointer)
	{
		this.pointer = pointer;
	}
	
	/**
	 * Returns the current block id
	 * 
	 * @return
	 * @throws IllegalStateException
	 */
	public int getBlockId() throws IllegalStateException
	{
		return this.blocks.getBlock(this.blockPos);
	}
	
	/**
	 * Returns the ids of all following blocks
	 * 
	 * @return
	 * @throws IllegalStateException
	 */
	public int[] getBlocks() throws IllegalStateException
	{
		int[] bl = new int[this.blocks.size() - this.blockPos];
		for (int i = 0; i < bl.length; i++)
			bl[i] = this.blocks.getBlock(this.blockPos + i);
		return bl;
	}
	
	/**
	 * Increases the block pointer to the next block
	 * 
	 * @return
	 * @throws NoSuchElementException
	 * @throws IllegalStateException
	 */
	public int nextBlock() throws NoSuchElementException, IllegalStateException
	{
		this.blockPos++;
		
		if (this.blockPos >= this.blocks.size())
			throw new NoSuchElementException();
		
		return this.blocks.getBlock(this.blockPos);
	}
	
	/**
	 * Adds a block id the the list
	 * 
	 * @param blockid
	 * @throws IllegalStateException
	 */
	public void addBlock(int blockid) throws IllegalStateException
	{
		this.blocks.addBlock(blockid);
	}
	
	/**
	 * Returns the number of blocks between the current block and the end of the
	 * block list
	 * 
	 * @return
	 */
	public int countBlocks()
	{
		return this.blocks.size() - this.blockPos;
	}
	
	/**
	 * Checks if two BlockPlans are equal
	 * 
	 * @param compare
	 * @return
	 * @throws IllegalArgumentException
	 * if BlockPlans are incomparable
	 */
	public boolean equalTo(BlockPlan compare) throws IllegalArgumentException
	{
		if (this.blocks != compare.blocks)
			throw new IllegalArgumentException("Blocks not comparable");
		
		return this.pointer == compare.pointer && this.getBlockId() == compare.getBlockId();
	}
	
	/**
	 * Checks if this BlockPlan is greater than another one
	 * 
	 * @param compare
	 * @return
	 * @throws IllegalArgumentException
	 * if BlockPlans are incomparable
	 */
	public boolean greaterThan(BlockPlan compare) throws IllegalArgumentException
	{
		if (this.blocks != compare.blocks)
			throw new IllegalArgumentException("Blocks not comparable");
		
		if (this.blockPos == compare.blockPos)
			return this.pointer > compare.pointer;
		else
			return blockPos > compare.blockPos;
	}
	
	@Override
	public String toString()
	{
		if (this.blockPos >= 0)
			return "[" + this.blocks.getBlock(this.blockPos) + ", " + this.pointer + "] ";
		else
			return "[X]";
	}
	
	@Override
	public int compareTo(BlockPlan compare) throws IllegalArgumentException
	{
		if (this.equalTo(compare))
			return 0;
		else if (this.greaterThan(compare))
			return 1;
		else
			return -1;
	}
	
	@Override
	public boolean equals(Object compare)
	{
		if (compare instanceof BlockPlan)
			try
			{
				return this.equalTo((BlockPlan) compare);
			}
			catch (IllegalArgumentException e)
			{
				return false;
			}
		else
			return false;
	}
	
	@Override
	public BlockPlan clone() throws IllegalStateException
	{
		return new BlockPlan(this.pointer, this.blocks.getBlock(this.blockPos), this.blocks);
	}
	
}
