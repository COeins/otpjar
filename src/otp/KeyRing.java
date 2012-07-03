package otp;

import otp.helpr.BlockPlan;
import otp.response.KeyringResponse;

public abstract class KeyRing
{
	
	public static final int BLOCKTYPE_E = 0;
	public static final int BLOCKTYPE_A = 2;
	public static final int BLOCKTYPE_SOS = 4;
	
	public static final int PARTICIP_ME = -1;
	public static final int PARTICIP_OTHER = -2;
	
	/**
	 * Specifies the key-id and participant to be used. Needs to be called before
	 * initialize()
	 * 
	 * @param keyid
	 * The key-id
	 * @param participant
	 * The participant-id. May be 0 or 1
	 * @throws KeyringResponse
	 */
	public abstract void selectKey(byte[] keyid, int participant) throws KeyringResponse;
	
	/**
	 * Opens the key settings file, read configuration values and initialize key.
	 * The key-id and participant need to be specified first.
	 * 
	 * @throws KeyringResponse
	 */
	public abstract void initialize() throws KeyringResponse;
	
	/**
	 * Return the key-id. Needs to be initialized first.
	 * 
	 * @return The id of the key in use
	 * @throws KeyringResponse
	 */
	public abstract byte[] getKeyId() throws KeyringResponse;
	
	/**
	 * Returns the current participant-id. Needs to be initialized first.
	 * 
	 * @return The id of the current participant
	 * @throws KeyringResponse
	 */
	public abstract int getKeyOwner() throws KeyringResponse;
	
	/**
	 * Returns the minimum padding. Needs to be initialized first.
	 * 
	 * @return The minimum padding in bytes
	 * @throws KeyringResponse
	 */
	public abstract int getPaddingParam1() throws KeyringResponse;
	
	/**
	 * Returns the maximum padding. Needs to be initialized first.
	 * 
	 * @return The maximum padding in bytes
	 * @throws KeyringResponse
	 */
	public abstract int getPaddingParam2() throws KeyringResponse;
	
	/**
	 * Returns the authentication code length to be used with this key. Needs to
	 * be initialized first.
	 * 
	 * @return The authentication code length in bytes
	 * @throws KeyringResponse
	 */
	public abstract int getAuthLength() throws KeyringResponse;
	
	/**
	 * Get the current plan for given user / type
	 * 
	 * @param participant
	 * @param type
	 * @return
	 * @throws KeyringResponse
	 */
	public abstract BlockPlan getCurrentPlan(int participant, int type) throws KeyringResponse;
	
	/**
	 * Get an older plan for a given user / type or add new blocks to a current
	 * plan.
	 * 
	 * @param participant
	 * @param type
	 * @param init
	 * @return
	 * @throws KeyringResponse
	 */
	public abstract BlockPlan importPlan(int participant, int type, byte[] init) throws KeyringResponse;
	
	/**
	 * Sets a newer plan to be stored. Updating older plans will be resulting in
	 * an error.
	 * 
	 * @param participant
	 * @param type
	 * @param plan
	 * @throws KeyringResponse
	 */
	public abstract void updatePlan(int participant, int type, BlockPlan plan) throws KeyringResponse;
	
	/**
	 * Skips a certain number of bytes in a BlockPlan. Usefull to simulate message
	 * reading.
	 * 
	 * @param plan
	 * @param bytes
	 * @throws KeyringResponse
	 */
	public abstract void fastForwardPlan(BlockPlan plan, long bytes) throws KeyringResponse;
	
	/**
	 * Adds new blocks to a plan until window size is reached
	 * 
	 * @param plan
	 * @throws KeyringResponse
	 */
	public abstract void fillPlan(BlockPlan plan) throws KeyringResponse;
	
	/**
	 * Calculates how much bytes could be read from a BlockPlan without adding new
	 * blocks
	 * 
	 * @param enc_pos
	 * @return
	 */
	public abstract long remainingBytes(BlockPlan enc_pos);
	
	/**
	 * Checks and adds blocks to a certain users block list.
	 * 
	 * @param participant
	 * The user the blocks should be added to
	 * @param type
	 * The usage the blocks should be added to
	 * @param blocks
	 * All blocks coded as 4-byte-ids in an array
	 * @param startPos
	 * The arrays starting position
	 * @throws KeyringResponse
	 */
	public abstract void addBlocks(int participant, int type, byte[] blocks, int startPos) throws KeyringResponse;
	
	/**
	 * Checks if a message is known or new, and if new if only new OTP areas are
	 * used.
	 * 
	 * @param hash
	 * The hash value of the message in question
	 * @param eStart
	 * Blockplan describing the start of the encryption
	 * @param eEnd
	 * Blockplan describing the end of the encryption
	 * @param aStart
	 * Blockplan describing the start of the authentication
	 * @param aEnd
	 * Blockplan describing the end of the encryption
	 * @return [0] message is ok, [1] message is new
	 * @throws KeyringResponse
	 */
	public abstract boolean[] verifyMessage(byte[] hash, BlockPlan eStart, BlockPlan eEnd, BlockPlan aStart,
			BlockPlan aEnd) throws KeyringResponse;
	
	/**
	 * Checks if key is marked in sync.
	 * 
	 * @return
	 * @throws KeyringResponse
	 */
	public abstract boolean keyInSync() throws KeyringResponse;
	
	/**
	 * Marks the key in / out of sync. Marking a key out of sync will disable all
	 * keys in its key ring
	 * 
	 * @param inSync
	 * @throws KeyringResponse
	 */
	public abstract void keySetSync(boolean inSync) throws KeyringResponse;
	
	/**
	 * Returns the last known positions from a partner, if their key is suspected
	 * out of sync
	 * 
	 * @return
	 * @throws KeyringResponse
	 */
	public abstract BlockPlan[] keyGetPartnerSync() throws KeyringResponse;
	
	/**
	 * Defines the last known positions from a partner, if their key is suspected
	 * out of sync
	 * 
	 * @param partnerPlans
	 * @throws KeyringResponse
	 */
	public abstract void keySetPartnerSync(BlockPlan[] partnerPlans) throws KeyringResponse;
	
	/**
	 * Initialized and the calling operation finished successfully stores all key
	 * values and closes the settings file. Otherwise only closes settings file.
	 * 
	 * @param success
	 * True, if the calling operation completed successfully.
	 * @return The result of the operation
	 */
	public abstract KeyringResponse finish(boolean success);
	
}
