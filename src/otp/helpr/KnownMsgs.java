package otp.helpr;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class KnownMsgs
{
	private final static int hashLen = 32;
	
	private List<byte[]> msgHashes;
	private List<BlockPlan[]> mAreas;
	
	public KnownMsgs(byte[] hashes, byte[] areas, BlockAssignList[] blocks) throws IllegalArgumentException,
			IllegalStateException
	{
		this.msgHashes = new LinkedList<byte[]>();
		if (hashes == null)
			hashes = new byte[0];
		
		if (areas == null)
			areas = new byte[0];
		
		for (int i = 0; i < hashes.length; i += KnownMsgs.hashLen)
		{
			byte[] cpy = new byte[KnownMsgs.hashLen];
			System.arraycopy(hashes, i, cpy, 0, KnownMsgs.hashLen);
			this.msgHashes.add(cpy);
		}
		
		this.mAreas = new LinkedList<BlockPlan[]>();
		
		for (int i = 0; i < areas.length; i += 16)
		{
			byte[] cpyA = new byte[8];
			byte[] cpyB = new byte[8];
			System.arraycopy(areas, i, cpyA, 0, 8);
			System.arraycopy(areas, i + 8, cpyB, 0, 8);
			
			int j = 0;
			boolean success = false;
			do
			{
				try
				{
					BlockPlan planA = new BlockPlan(cpyA, blocks[j]);
					BlockPlan planB = new BlockPlan(cpyB, blocks[j]);
					success = true;
					this.mAreas.add(new BlockPlan[] { planA, planB });
				}
				catch (IllegalStateException e)
				{
					j++;
				}
				
				if (j >= blocks.length)
					throw new IllegalStateException("Inconsistent Usage Areas");
			}
			while (!success);
		}
		
	}
	
	/**
	 * Returns a byte array containing all stored hash values
	 * 
	 * @return
	 */
	public byte[] exportHashes()
	{
		ByteArrayBuilder exp = new ByteArrayBuilder();
		for (int i = 0; i < this.msgHashes.size(); i++)
			exp.addAll(msgHashes.get(i));
		
		return exp.toArray();
	}
	
	/**
	 * Returns a byte array containing all stored otp areas
	 * 
	 * @return
	 */
	public byte[] exportAreas()
	{
		ByteArrayBuilder exp = new ByteArrayBuilder();
		for (int i = 0; i < this.mAreas.size(); i++)
		{
			exp.addAll(mAreas.get(i)[0].exportPlanShort());
			exp.addAll(mAreas.get(i)[1].exportPlanShort());
		}
		return exp.toArray();
	}
	
	/**
	 * Checks if a given message is legitamit. To be acepted, new messages have to
	 * occupy unused OTP areas. Also stores the given areas and hashes.
	 * 
	 * @param hash
	 * The message hash
	 * @param eStart
	 * The encryption start
	 * @param eEnd
	 * The encryption end
	 * @param aStart
	 * The Authenticaton Start
	 * @param aEnd
	 * The Authentication End
	 * @return [0] message is ok, [1] message is new
	 * @throws IllegalArgumentException
	 */
	public boolean[] isLegit(byte[] hash, BlockPlan eStart, BlockPlan eEnd, BlockPlan aStart, BlockPlan aEnd)
			throws IllegalArgumentException
	{
		if (hash.length != KnownMsgs.hashLen)
			throw new IllegalStateException("Hash size does not match");
		
		boolean contains = false;
		for (int i = 0; i < this.msgHashes.size() && !contains; i++)
			if (Arrays.equals(this.msgHashes.get(i), hash))
				contains = true;
		
		if (contains)
		{
			return new boolean[] { true, false };
		}
		else
		{
			// attach to list
			this.msgHashes.add(hash);
			
			for (int h = 0; h < 2; h++)
			{
				BlockPlan mStart, mEnd;
				if (h == 0)
				{
					mStart = eStart;
					mEnd = eEnd;
				}
				else
				{
					mStart = aStart;
					mEnd = aEnd;
				}
				
				int startPos = -1;
				int endPos = -1;
				
				// check if overlaps with already used key areas
				for (int i = 0; i < this.mAreas.size(); i++)
				{
					BlockPlan blStart = this.mAreas.get(i)[0];
					BlockPlan blEnd = this.mAreas.get(i)[1];
					try
					{
						
						if ((blEnd.greaterThan(mStart) && !blStart.greaterThan(mStart)) ||
								(mEnd.greaterThan(blStart) && !mEnd.greaterThan(blEnd)) ||
								(!mStart.greaterThan(blStart) && !blEnd.greaterThan(mEnd)))
							return new boolean[] { false, false };
						
						if (this.mAreas.get(i)[1].equalTo(mStart))
							startPos = i;
						if (this.mAreas.get(i)[0].equalTo(mEnd))
							endPos = i;
					}
					catch (IllegalArgumentException e)
					{
						// incomparable positions, nothing to do here
					}
				}
				
				if (startPos > -1 & endPos > -1) // unite areas
				{
					this.mAreas.get(startPos)[1] = this.mAreas.get(endPos)[1];
					this.mAreas.remove(endPos);
				}
				else if (startPos > -1) // extend area right
				{
					this.mAreas.get(startPos)[1] = mEnd;
				}
				else if (endPos > -1) // extend area left
				{
					this.mAreas.get(endPos)[0] = mStart;
				}
				else
				// add new area
				{
					this.mAreas.add(new BlockPlan[] { mStart, mEnd });
				}
			}
			return new boolean[] { true, true };
		}
	}
	
	@Override
	public String toString()
	{
		StringBuilder sb = new StringBuilder();
		
		sb.append(this.msgHashes.size() + " messages, " + this.mAreas.size() + " areas");
		
		for (int i = 0; i < this.mAreas.size(); i++)
			sb.append("\n " + this.mAreas.get(i)[0] + "- " + this.mAreas.get(i)[1]);
		
		return sb.toString();
	}
}
