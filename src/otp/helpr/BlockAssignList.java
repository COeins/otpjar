package otp.helpr;

import java.util.LinkedList;
import java.util.List;

public class BlockAssignList
{
	private List<Integer> blocks;
	private BlockAssignList[] others;
	
	public BlockAssignList(BlockAssignList[] others)
	{
		this.blocks = new LinkedList<Integer>();
		this.others = others;
	}
	
	public BlockAssignList(byte[] importList, BlockAssignList[] others)
	{
		this.blocks = new LinkedList<Integer>();
		
		byte[] n = new byte[4];
		
		for (int i = 0; i < importList.length; i += 4)
		{
			System.arraycopy(importList, i, n, 0, 4);
			this.blocks.add(ByteArray.toInt(n));
		}
		
		this.others = others;
	}
	
	/**
	 * Generates a byte array containing all block ids
	 * 
	 * @return
	 */
	public byte[] exportList()
	{
		ByteArrayBuilder out = new ByteArrayBuilder();
		for (int i = 0; i < this.blocks.size(); i++)
			out.addAll(ByteArray.fromInt(this.blocks.get(i)));
		return out.toArray();
	}
	
	/**
	 * Checks if a certain block id is contained in the list
	 * 
	 * @param blockid
	 * @return
	 */
	public boolean containsBlock(int blockid)
	{
		return this.blocks.contains(new Integer(blockid));
	}
	
	/**
	 * Returns the list position of a certain block id
	 * 
	 * @param blockid
	 * @return
	 */
	public int blockPos(int blockid)
	{
		Integer i = new Integer(blockid);
		return this.blocks.indexOf(i);
	}
	
	/**
	 * Return the block id of a certain list position
	 * 
	 * @param pos
	 * @return
	 * @throws IllegalStateException
	 */
	public int getBlock(int pos) throws IllegalStateException
	{
		if (pos >= this.blocks.size())
			throw new IllegalStateException("Requestet block does not exist");
		return this.blocks.get(pos);
	}
	
	/**
	 * Adds a block id the the list
	 * 
	 * @param blockid
	 */
	public void addBlock(int blockid)
	{
		
		Integer i = new Integer(blockid);
		
		for (int j = 0; j < this.others.length; j++)
			if (this.others[j].containsBlock(i))
			{
				System.out.println("skipping Duplicate block " + blockid);
				throw new IllegalStateException("Duplicate block detected");
			}
		
		this.blocks.add(i);
	}
	
	/**
	 * Returns the list size
	 * 
	 * @return
	 */
	public int size()
	{
		return this.blocks.size();
	}
	
	@Override
	public String toString()
	{
		StringBuilder out = new StringBuilder();
		
		for (int i = 0; i < this.blocks.size(); i++)
			out.append("[" + this.blocks.get(i) + "] ");
		
		return out.toString();
	}
	
}
