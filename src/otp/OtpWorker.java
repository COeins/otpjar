package otp;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import otp.helpr.BlockPlan;
import otp.helpr.ByteArray;
import otp.response.KeyringResponse;
import otp.response.Response;
import otp.response.RngResponse;
import otp.response.WorkResponse;

public class OtpWorker
{
	private final static int blocksize = 16;
	private final static int headerLength = 22;
	
	private final static int syncValidityThreshold = 60 * 60 * 24 * 7;
	// 1 week in seconds
	
	private final static int ACTION_ENCRYPT = 0;
	private final static int ACTION_DECRYPT = 1;
	
	/**
	 * prevents instantiation of objects from this class
	 */
	private OtpWorker()
	{
		
	}
	
	/**
	 * Encrypts the specified file or stream
	 * 
	 * @param ring
	 * Settings for the key to be used, with key-id set
	 * @param in
	 * Input file to be encrypted
	 * @param out
	 * Output file for the result to be written to
	 * @param encOtp
	 * Otp used for encryption
	 * @param authOtp
	 * Otp used for authentication
	 * @param auth
	 * Authentication method
	 * @param rng
	 * Random number generator
	 * @param ui
	 * User interface
	 * @return Result of encryption operation
	 */
	public static Result encrypt(KeyRing ring, Infile in, Outfile out, Otp encOtp, Otp authOtp, Authenticator auth,
			Rng rng, UserInterface ui)
	{
		Result res = new Result();
		boolean success = false;
		
		try
		{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			rng.initialize();
			in.initialize();
			out.initialize();
			
			ring.initialize();
			encOtp.initialize();
			authOtp.initialize();
			
			if (!ring.keyInSync())
				throw new WorkResponse(12);
			
			BlockPlan eStart = ring.getCurrentPlan(KeyRing.PARTICIP_ME, KeyRing.BLOCKTYPE_E);
			BlockPlan aStart = ring.getCurrentPlan(KeyRing.PARTICIP_ME, KeyRing.BLOCKTYPE_A);
			
			encOtp.setPosition(eStart.clone());
			authOtp.setPosition(aStart.clone());
			
			long fileLength = in.getLength();
			int paddingLength = OtpWorker.getPaddingLength(ring.getPaddingParam1(), ring.getPaddingParam2(), rng);
			
			byte[] header = new byte[OtpWorker.headerLength];
			
			byte[] otherPlanE = ring.getCurrentPlan(KeyRing.PARTICIP_OTHER, KeyRing.BLOCKTYPE_E).exportPlanComplete();
			
			byte[] otherPlanA = ring.getCurrentPlan(KeyRing.PARTICIP_OTHER, KeyRing.BLOCKTYPE_A).exportPlanComplete();
			byte[] keySync = new byte[10 + otherPlanE.length + otherPlanA.length];
			
			long size = keySync.length + 9 + fileLength + paddingLength;
			
			if (ring.remainingBytes(eStart) < size)
				throw new WorkResponse(7);
			
			if (ring.remainingBytes(aStart) < auth.setInputSize(size + OtpWorker.headerLength))
				throw new WorkResponse(7);
			
			auth.initialize();
			
			header[0] = 2; // message format version
			System.arraycopy(ring.getKeyId(), 0, header, 1, 4);
			header[5] = (byte) ring.getKeyOwner();
			System.arraycopy(eStart.exportPlanShort(), 0, header, 6, 8);
			System.arraycopy(aStart.exportPlanShort(), 0, header, 14, 8);
			
			out.write(header);
			auth.next(header);
			md.update(header);
			
			keySync[0] = 3; // Type Key-Sync container
			keySync[1] = (byte) (1 - ring.getKeyOwner());
			System.arraycopy(ByteArray.fromInt(otherPlanE.length), 0, keySync, 2, 4);
			System.arraycopy(ByteArray.fromInt(otherPlanA.length), 0, keySync, 6, 4);
			System.arraycopy(otherPlanE, 0, keySync, 10, otherPlanE.length);
			System.arraycopy(otherPlanA, 0, keySync, 10 + otherPlanE.length, otherPlanA.length);
			byte[] ksEnc = ByteArray.xor(keySync, encOtp.next(keySync.length));
			
			out.write(ksEnc);
			auth.next(ksEnc);
			md.update(ksEnc);
			
			byte[] bodyHeader = new byte[9];
			bodyHeader[0] = 1; // Type Body container
			System.arraycopy(ByteArray.fromLong(fileLength), 0, bodyHeader, 1, 8);
			byte[] bhEnc = ByteArray.xor(bodyHeader, encOtp.next(bodyHeader.length));
			
			out.write(bhEnc);
			auth.next(bhEnc);
			md.update(bhEnc);
			
			cryptWorkload(null, OtpWorker.ACTION_ENCRYPT, in, out, auth, encOtp, ui, md);
			
			byte[] padding = rng.next(paddingLength);
			while (padding[0] > 0 && padding[0] < 10)
				padding[0] = rng.next();
			// Don't mimic other container types
			
			byte[] paddE = ByteArray.xor(padding, encOtp.next(padding.length));
			out.write(paddE);
			auth.next(paddE);
			md.update(paddE);
			
			byte[] mac = auth.doFinal();
			
			out.write(mac);
			md.update(mac);
			
			BlockPlan eEnd = encOtp.getPosition();
			BlockPlan aEnd = authOtp.getPosition();
			
			ui.verboseMessage("Message areas: " + eStart + "- " + eEnd + ", " + aStart + "- " + aEnd);
			
			if (!ring.verifyMessage(md.digest(), eStart, eEnd, aStart, aEnd)[0])
				throw new WorkResponse(0);
			
			ring.updatePlan(KeyRing.PARTICIP_ME, KeyRing.BLOCKTYPE_E, eEnd);
			ring.updatePlan(KeyRing.PARTICIP_ME, KeyRing.BLOCKTYPE_A, aEnd);
			
			success = true;
		}
		catch (Response e)
		{
			res.add(e);
		}
		catch (NoSuchAlgorithmException e)
		{
			res.add(new WorkResponse(0, e));
		}
		finally
		{
			res.add(in.finish(success));
			res.add(out.finish(success));
			res.add(auth.finish(success));
			res.add(encOtp.finish(success));
			res.add(authOtp.finish(success));
			res.add(ring.finish(success));
			res.add(rng.finish(success));
		}
		return res;
	}
	
	/**
	 * Decrypts the specified file or stream
	 * 
	 * @param ring
	 * Settings for the key to be used, without key-id set
	 * @param in
	 * Input file to be decrypted
	 * @param out
	 * Output file for the result to be written to
	 * @param encOtp
	 * Otp used for encryption
	 * @param authOtp
	 * Otp used for authentication
	 * @param auth
	 * Authentication method
	 * @param rng
	 * Random number generator
	 * @param ui
	 * User interface
	 * @return Result of decryption operation
	 */
	public static Result decrypt(KeyRing ring, Infile in, Outfile out, Otp encOtp, Otp authOtp, Authenticator auth,
			Rng rng, UserInterface ui, boolean newmsg)
	{
		
		Result res = new Result();
		boolean success = false;
		boolean sosMessage = false;
		try
		{
			rng.initialize();
			in.initialize();
			out.initialize();
			
			byte[] header = new byte[OtpWorker.headerLength];
			in.read(header);
			
			if (header[0] != 2)
				throw new WorkResponse(1);
			
			byte[] padId = new byte[4];
			System.arraycopy(header, 1, padId, 0, 4);
			
			int participant = header[5];
			
			byte[] encPos = new byte[8];
			byte[] authPos = new byte[8];
			
			System.arraycopy(header, 6, encPos, 0, 8);
			System.arraycopy(header, 14, authPos, 0, 8);
			
			ring.selectKey(padId, participant);
			ring.initialize();
			encOtp.initialize();
			authOtp.initialize();
			
			BlockPlan ePlan, aPlan;
			try
			// normal blocks
			{
				ePlan = ring.importPlan(participant, KeyRing.BLOCKTYPE_E, encPos);
				aPlan = ring.importPlan(participant, KeyRing.BLOCKTYPE_A, authPos);
			}
			catch (KeyringResponse r)
			{
				if (r.getErrorCode() == 10) // try sos blocks
				{
					ePlan = ring.importPlan(participant, KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS, encPos);
					aPlan = ring.importPlan(participant, KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS, authPos);
					sosMessage = true;
				}
				else
					throw r;
			}
			
			encOtp.setPosition(ePlan);
			authOtp.setPosition(aPlan);
			
			long filelength = in.getLength();
			
			long messageLength = filelength - OtpWorker.headerLength - ring.getAuthLength();
			
			auth.setInputSize(messageLength + OtpWorker.headerLength);
			auth.initialize();
			auth.next(header);
			
			long read = 0;
			long bodyLength = 0;
			
			while (read < messageLength)
			{
				byte[] typeEnc = in.read(1);
				auth.next(typeEnc);
				byte[] typeKey = encOtp.next(1);
				byte type = ByteArray.xor(typeKey, typeEnc)[0];
				read++;
				
				switch (type)
				{
					case 1: // normal content
						if (sosMessage)
							throw new WorkResponse(11);
						byte[] containerHeaderEnc = in.read(8);
						auth.next(containerHeaderEnc);
						bodyLength = ByteArray.toLong(ByteArray.xor(encOtp.next(8), containerHeaderEnc));
						
						cryptWorkload(bodyLength, OtpWorker.ACTION_DECRYPT, in, out, auth, encOtp, ui, null);
						read += 8 + bodyLength;
						break;
					
					case 2: // compressed content
						if (sosMessage)
							throw new WorkResponse(11);
						ui.warningMessage("Blocktype unsupported " + typeEnc[0] + " (+) " + typeKey[0] + " = " + type);
						throw new WorkResponse(6);
						// break;
						
					case 3: // normal key management
						if (sosMessage)
							throw new WorkResponse(11);
						
						byte[] ksParticipEnc = in.read(1);
						auth.next(ksParticipEnc);
						byte[] kskey1 = encOtp.next(1);
						byte ksParticip = ByteArray.xor(ksParticipEnc, kskey1)[0];
						
						if (ksParticip == participant)
							throw new WorkResponse(0);
						
						byte[] eotpLenEnc = in.read(4);
						auth.next(eotpLenEnc);
						byte[] kskey2 = encOtp.next(4);
						byte[] eotpLen = ByteArray.xor(eotpLenEnc, kskey2);
						
						byte[] aotpLenEnc = in.read(4);
						auth.next(aotpLenEnc);
						byte[] kskey3 = encOtp.next(4);
						byte[] aotpLen = ByteArray.xor(aotpLenEnc, kskey3);
						
						int eLen = ByteArray.toInt(eotpLen);
						int aLen = ByteArray.toInt(aotpLen);
						
						if (eLen < 0 || eLen % 4 > 0 || eLen < 0 || eLen % 4 > 0)
							throw new WorkResponse(3);
						
						byte[] eotpEnc = in.read(eLen);
						auth.next(eotpEnc);
						byte[] kskey4 = encOtp.next(eLen);
						byte[] ksEotp = ByteArray.xor(eotpEnc, kskey4);
						
						byte[] aotpEnc = in.read(aLen);
						auth.next(aotpEnc);
						byte[] kskey5 = encOtp.next(aLen);
						byte[] ksAotp = ByteArray.xor(aotpEnc, kskey5);
						
						read += 9 + eLen + aLen;
						
						if (newmsg && participant != ring.getKeyOwner())
						{
							try
							{
								BlockPlan ksEnewPlan = ring.importPlan(ksParticip, KeyRing.BLOCKTYPE_E, ksEotp);
								BlockPlan ksAnewPlan = ring.importPlan(ksParticip, KeyRing.BLOCKTYPE_A, ksAotp);
								
								BlockPlan ksEcurPlan = ring.getCurrentPlan(ksParticip, KeyRing.BLOCKTYPE_E);
								BlockPlan ksAcurPlan = ring.getCurrentPlan(ksParticip, KeyRing.BLOCKTYPE_A);
								ring.addBlocks(ksParticip, KeyRing.BLOCKTYPE_E, ksEotp, 4);
								ring.addBlocks(ksParticip, KeyRing.BLOCKTYPE_A, ksAotp, 4);
								
								if (ksEnewPlan.greaterThan(ksEcurPlan) || ksAnewPlan.greaterThan(ksAcurPlan))
								{
									if (ring.keyInSync())
									{
										ring.keySetSync(false);
										throw new WorkResponse(12);
									}
								}
							}
							catch (KeyringResponse r)
							{
								if (ring.keyInSync())
								{
									ring.keySetSync(false);
									throw new WorkResponse(12);
								}
							}
						}
						break;
					
					case 4: // sync-req
						if (!sosMessage)
							throw new WorkResponse(10);
						byte[] pLenE = in.read(1);
						auth.next(pLenE);
						byte[] pLenK = encOtp.next(1);
						byte[] pl = { 0, 0, 0, ByteArray.xor(pLenE, pLenK)[0] };
						int pLen = ByteArray.toInt(pl);
						read++;
						
						byte[] paddE = in.read(pLen);
						auth.next(paddE);
						encOtp.next(pLen);
						read += pLen;
						
						BlockPlan[] syncPlans = new BlockPlan[4];
						{
							byte[] sync0eE = in.read(8);
							auth.next(sync0eE);
							byte[] sync0eP = ByteArray.xor(sync0eE, encOtp.next(8));
							
							byte[] sync0aE = in.read(8);
							auth.next(sync0aE);
							byte[] sync0aP = ByteArray.xor(sync0aE, encOtp.next(8));
							
							byte[] sync1eE = in.read(8);
							auth.next(sync1eE);
							byte[] sync1eP = ByteArray.xor(sync1eE, encOtp.next(8));
							
							byte[] sync1aE = in.read(8);
							auth.next(sync1aE);
							byte[] sync1aP = ByteArray.xor(sync1aE, encOtp.next(8));
							read += 32;
							
							if (newmsg && participant != ring.getKeyOwner())
							{
								try
								{
									syncPlans[KeyRing.BLOCKTYPE_E | 0] = ring.importPlan(0, KeyRing.BLOCKTYPE_E, sync0eP);
									syncPlans[KeyRing.BLOCKTYPE_A | 0] = ring.importPlan(0, KeyRing.BLOCKTYPE_A, sync0aP);
									syncPlans[KeyRing.BLOCKTYPE_E | 1] = ring.importPlan(1, KeyRing.BLOCKTYPE_E, sync1eP);
									syncPlans[KeyRing.BLOCKTYPE_A | 1] = ring.importPlan(1, KeyRing.BLOCKTYPE_A, sync1aP);
								}
								catch (KeyringResponse r)
								{
									throw new WorkResponse(11, r);
								}
								ring.keySetPartnerSync(syncPlans);
								// ui.warningMessage("Key-sync request recieved. Please generate and send a sync message as soon as possible by using the '--syncronize' parameter.");
								res.add(new WorkResponse(true, 13));
							}
							else
							{
								if (newmsg)
									throw new WorkResponse(11);
								else
									throw new WorkResponse(14);
							}
						}
						break;
					
					case 5: // sync-ack
						if (!sosMessage)
							throw new WorkResponse(10);
						
						ui.message("Syncing key...");
						
						byte[] dateE = in.read(4);
						auth.next(dateE);
						int dateP = ByteArray.toInt(ByteArray.xor(dateE, encOtp.next(4)));
						int now = (int) (System.currentTimeMillis() / 1000);
						
						// current date has to be within message creation and validity
						// treshold
						if (dateP > now + 60 || dateP + OtpWorker.syncValidityThreshold < now)
							throw new WorkResponse(16);
						
						byte[] sync0eLenE = in.read(4);
						auth.next(sync0eLenE);
						int sync0eLenP = ByteArray.toInt(ByteArray.xor(sync0eLenE, encOtp.next(4)));
						
						byte[] sync0aLenE = in.read(4);
						auth.next(sync0aLenE);
						int sync0aLenP = ByteArray.toInt(ByteArray.xor(sync0aLenE, encOtp.next(4)));
						
						byte[] sync1eLenE = in.read(4);
						auth.next(sync1eLenE);
						int sync1eLenP = ByteArray.toInt(ByteArray.xor(sync1eLenE, encOtp.next(4)));
						
						byte[] sync1aLenE = in.read(4);
						auth.next(sync1aLenE);
						int sync1aLenP = ByteArray.toInt(ByteArray.xor(sync1aLenE, encOtp.next(4)));
						
						byte[] sync0eE = in.read(sync0eLenP);
						auth.next(sync0eE);
						byte[] sync0eP = ByteArray.xor(sync0eE, encOtp.next(sync0eLenP));
						
						byte[] sync0aE = in.read(sync0aLenP);
						auth.next(sync0aE);
						byte[] sync0aP = ByteArray.xor(sync0aE, encOtp.next(sync0aLenP));
						
						byte[] sync1eE = in.read(sync1eLenP);
						auth.next(sync1eE);
						byte[] sync1eP = ByteArray.xor(sync1eE, encOtp.next(sync1eLenP));
						
						byte[] sync1aE = in.read(sync1aLenP);
						auth.next(sync1aE);
						byte[] sync1aP = ByteArray.xor(sync1aE, encOtp.next(sync1aLenP));
						
						byte[] syncSoseE = in.read(8);
						auth.next(syncSoseE);
						byte[] syncSoseP = ByteArray.xor(syncSoseE, encOtp.next(8));
						
						byte[] syncSosaE = in.read(8);
						auth.next(syncSosaE);
						byte[] syncSosaP = ByteArray.xor(syncSosaE, encOtp.next(8));
						
						read += sync0eLenP + sync0aLenP + sync1eLenP + sync1aLenP + 36;
						
						if (newmsg && participant != ring.getKeyOwner())
						{
							
							BlockPlan[] syncPlan = new BlockPlan[8];
							int me = ring.getKeyOwner();
							
							ring.addBlocks(0, KeyRing.BLOCKTYPE_E, sync0eP, 4);
							ring.addBlocks(0, KeyRing.BLOCKTYPE_A, sync0aP, 4);
							ring.addBlocks(1, KeyRing.BLOCKTYPE_E, sync1eP, 4);
							ring.addBlocks(1, KeyRing.BLOCKTYPE_A, sync1aP, 4);
							
							syncPlan[0 | KeyRing.BLOCKTYPE_E] = ring.importPlan(0, KeyRing.BLOCKTYPE_E, sync0eP);
							syncPlan[0 | KeyRing.BLOCKTYPE_A] = ring.importPlan(0, KeyRing.BLOCKTYPE_A, sync0aP);
							syncPlan[1 | KeyRing.BLOCKTYPE_E] = ring.importPlan(1, KeyRing.BLOCKTYPE_E, sync1eP);
							syncPlan[1 | KeyRing.BLOCKTYPE_A] = ring.importPlan(1, KeyRing.BLOCKTYPE_A, sync1aP);
							
							syncPlan[me | KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS] = ring.importPlan(me, KeyRing.BLOCKTYPE_E |
									KeyRing.BLOCKTYPE_SOS, syncSoseP);
							syncPlan[me | KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS] = ring.importPlan(me, KeyRing.BLOCKTYPE_A |
									KeyRing.BLOCKTYPE_SOS, syncSosaP);
							
							boolean possible = true;
							int[] syncTypes = { 0 | KeyRing.BLOCKTYPE_E, 0 | KeyRing.BLOCKTYPE_A, 1 | KeyRing.BLOCKTYPE_E,
									1 | KeyRing.BLOCKTYPE_A, me | KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS,
									me | KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS, };
							
							for (int bType : syncTypes)
							{
								BlockPlan curPlan = ring.getCurrentPlan(0, bType);
								if (curPlan.greaterThan(syncPlan[bType]))
								{
									possible = false;
								}
							}
							
							if (ring.keyInSync())
							{
								if (syncPlan[me | KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS].greaterThan(ring.getCurrentPlan(me,
										KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS)) ||
										syncPlan[me | KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS].greaterThan(ring.getCurrentPlan(me,
												KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS)))
									ring.keySetSync(false);
							}
							
							if (possible)
							{
								for (int bType : syncTypes)
								{
									ring.updatePlan(0, bType, syncPlan[bType]);
								}
								ring.keySetSync(true);
								// ui.warningMessage("Key synced successfully.");
								res.add(new WorkResponse(true, 15));
							}
							else
								throw new WorkResponse(11);
							
						}
						else
							throw new WorkResponse(14);
						break;
					
					default:
						// message padding
						byte[] padd = new byte[OtpWorker.blocksize];
						byte[] paddKey = new byte[OtpWorker.blocksize];
						while (read < messageLength)
						{
							if (messageLength - read < padd.length)
							{
								padd = new byte[(int) (messageLength - read)];
								paddKey = new byte[(int) (messageLength - read)];
							}
							
							in.read(padd);
							auth.next(padd);
							encOtp.next(paddKey);
							
							read += padd.length;
						}
						break;
				
				}
			}
			
			byte[] mac = auth.doFinal();
			byte[] mac2 = in.read(mac.length);
			
			if (!Arrays.equals(mac, mac2))
				throw new WorkResponse(2);
			
			if (!sosMessage && bodyLength == 0)
			{
				ui.warningMessage("Decoded message does not contain any output data");
			}
			
			BlockPlan eEndPlan = encOtp.getPosition();
			BlockPlan aEndPlan = authOtp.getPosition();
			
			if (sosMessage)
			{
				ring.updatePlan(participant, KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS, eEndPlan);
				ring.updatePlan(participant, KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS, aEndPlan);
			}
			else
			{
				if (participant != ring.getKeyOwner())
				{
					ring.fillPlan(eEndPlan);
					ring.fillPlan(aEndPlan);
				}
				
				ring.updatePlan(participant, KeyRing.BLOCKTYPE_E, eEndPlan);
				ring.updatePlan(participant, KeyRing.BLOCKTYPE_A, aEndPlan);
			}
			success = true;
		}
		catch (Response e)
		{
			res.add(e);
		}
		finally
		{
			res.add(in.finish(success));
			res.add(out.finish(success));
			res.add(auth.finish(success));
			res.add(encOtp.finish(success));
			res.add(authOtp.finish(success));
			res.add(ring.finish(success));
			res.add(rng.finish(success));
		}
		return res;
	}
	
	/**
	 * Verifies the authentication of the given input
	 * 
	 * @param ring
	 * Settings for the key to be used, without key-id set
	 * @param in
	 * Input file to be verified
	 * @param authOtp
	 * Otp used for authentication
	 * @param auth
	 * Authentication method
	 * @param rng
	 * Random number generator
	 * @param ui
	 * User interface
	 * @return Result of verification
	 */
	public static Result verify(KeyRing ring, Infile in, Otp authOtp, Authenticator auth, Rng rng, UserInterface ui,
			boolean[] mi)
	{
		
		Result res = new Result();
		boolean success = false;
		if (mi == null || mi.length < 2)
			mi = new boolean[2];
		
		boolean sosMessage = false;
		
		try
		{
			rng.initialize();
			in.initialize();
			
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			
			byte[] header = new byte[OtpWorker.headerLength];
			in.read(header);
			md.update(header);
			
			if (header[0] != 2)
				throw new WorkResponse(1);
			
			byte[] padId = new byte[4];
			System.arraycopy(header, 1, padId, 0, 4);
			
			int participant = header[5];
			
			byte[] encPos = new byte[8];
			byte[] authPos = new byte[8];
			
			System.arraycopy(header, 6, encPos, 0, 8);
			System.arraycopy(header, 14, authPos, 0, 8);
			
			ring.selectKey(padId, participant);
			ring.initialize();
			
			BlockPlan eStartPlan, aStartPlan;
			try
			// normal blocks
			{
				eStartPlan = ring.importPlan(participant, KeyRing.BLOCKTYPE_E, encPos);
				aStartPlan = ring.importPlan(participant, KeyRing.BLOCKTYPE_A, authPos);
			}
			catch (KeyringResponse r)
			{
				if (r.getErrorCode() == 10) // try sos blocks
				{
					try
					{
						eStartPlan = ring.importPlan(participant, KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS, encPos);
						aStartPlan = ring.importPlan(participant, KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS, authPos);
						sosMessage = true;
					}
					catch (KeyringResponse s)
					{
						// maybe try temporary block list
						// if (s.getErrorCode() == 10)
						// {
						// }
						// else
						throw new WorkResponse(9);
					}
				}
				else
					throw r;
			}
			
			authOtp.setPosition(aStartPlan.clone());
			authOtp.initialize();
			
			long filelength = in.getLength();
			long messageLength = filelength - OtpWorker.headerLength - ring.getAuthLength();
			
			auth.setInputSize(messageLength + OtpWorker.headerLength);
			auth.initialize();
			auth.next(header);
			
			long read = 0;
			byte[] inx = new byte[OtpWorker.blocksize];
			
			ui.initializeProgress(messageLength);
			
			for (; read < messageLength - OtpWorker.blocksize; read += OtpWorker.blocksize)
			{
				in.read(inx);
				md.update(inx);
				auth.next(inx);
				ui.updateProgress(read);
			}
			
			if (read < messageLength)
			{
				inx = new byte[(int) (messageLength - read)];
				in.read(inx);
				md.update(inx);
				auth.next(inx);
				read += inx.length;
			}
			
			byte[] authCode = in.read(auth.getMacLength());
			md.update(authCode);
			
			byte[] mac = auth.doFinal();
			
			ui.finishProgress();
			
			if (!Arrays.equals(mac, authCode))
				throw new WorkResponse(2);
			
			BlockPlan eEndPlan = eStartPlan.clone();
			try
			{
				ring.fastForwardPlan(eEndPlan, read);
			}
			catch (KeyringResponse r)
			{
				if (r.getErrorCode() == 9)
				{
					throw new WorkResponse(9, r);
				}
				else
					throw r;
			}
			
			BlockPlan aEndPlan = authOtp.getPosition();
			
			ui.verboseMessage("Message areas: " + eStartPlan + "- " + eEndPlan + ", " + aStartPlan + "- " + aEndPlan);
			
			boolean[] msginfo = ring.verifyMessage(md.digest(), eStartPlan, eEndPlan, aStartPlan, aEndPlan);
			mi[0] = msginfo[0];
			mi[1] = msginfo[1];
			
			if (!msginfo[0] && participant != ring.getKeyOwner())
			{
				if (sosMessage)
				{
					ring.updatePlan(participant, KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS, eEndPlan);
					ring.updatePlan(participant, KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS, aEndPlan);
					ring.keySetPartnerSync(null);
				}
				else
				{
					BlockPlan[] syncPlan = new BlockPlan[4];
					syncPlan[participant | KeyRing.BLOCKTYPE_E] = eEndPlan;
					syncPlan[participant | KeyRing.BLOCKTYPE_A] = aEndPlan;
					ring.keySetPartnerSync(syncPlan);
				}
				throw new WorkResponse(13);
			}
			
			if (sosMessage)
			{
				ring.updatePlan(participant, KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS, eEndPlan);
				ring.updatePlan(participant, KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS, aEndPlan);
			}
			else
			{
				if (participant == ring.getKeyOwner())
				{
					if (eEndPlan.greaterThan(ring.getCurrentPlan(participant, KeyRing.BLOCKTYPE_E)) ||
							aEndPlan.greaterThan(ring.getCurrentPlan(participant, KeyRing.BLOCKTYPE_A)))
					{
						if (ring.keyInSync())
						{
							ring.keySetSync(false);
							throw new WorkResponse(12);
						}
					}
					
				}
				ring.updatePlan(participant, KeyRing.BLOCKTYPE_E, eEndPlan);
				ring.updatePlan(participant, KeyRing.BLOCKTYPE_A, aEndPlan);
			}
			success = true;
		}
		catch (Response e)
		{
			res.add(e);
		}
		catch (NoSuchAlgorithmException e)
		{
			res.add(new WorkResponse(0, e));
		}
		finally
		{
			res.add(in.finish(success));
			res.add(auth.finish(success));
			res.add(authOtp.finish(success));
			res.add(ring.finish(success));
			res.add(rng.finish(success));
		}
		return res;
	}
	
	/**
	 * Modifies a key to achieve plausible deniability. The OTP will be changed in
	 * a way that decrypting one message will reveal a different message
	 * afterwards.
	 * 
	 * @param set
	 * The KeySettings of the OTP to be modified
	 * @param oldin
	 * The (encrypted) original message
	 * @param newin
	 * The (plain) new message
	 * @param eotp
	 * The OTP to be modified
	 * @param rng
	 * Random number generator
	 * @param ui
	 * The user interface
	 * @return
	 */
	public static Result modifyKey(KeyRing ring, Infile oldIn, Infile newIn, Otp encOtp, Otp authOtp, Authenticator auth,
			Rng rng, UserInterface ui)
	{
		
		Result res = new Result();
		boolean success = false;
		
		try
		{
			oldIn.initialize();
			rng.initialize();
			
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			
			byte[] header = new byte[OtpWorker.headerLength];
			oldIn.read(header);
			md.update(header);
			
			if (header[0] != 2)
				throw new WorkResponse(1);
			
			byte[] padId = new byte[4];
			System.arraycopy(header, 1, padId, 0, 4);
			
			int participant = header[5];
			
			byte[] encPos = new byte[8];
			byte[] authPos = new byte[8];
			
			System.arraycopy(header, 6, encPos, 0, 8);
			System.arraycopy(header, 14, authPos, 0, 8);
			
			ring.selectKey(padId, participant);
			ring.initialize();
			encOtp.initialize();
			authOtp.initialize();
			BlockPlan eStartPlan = ring.importPlan(participant, KeyRing.BLOCKTYPE_E, encPos);
			BlockPlan aStartPlan = ring.importPlan(participant, KeyRing.BLOCKTYPE_A, authPos);
			
			encOtp.setPosition(eStartPlan.clone());
			authOtp.setPosition(aStartPlan.clone());
			
			long filelength = oldIn.getLength();
			
			long messageLength = filelength - OtpWorker.headerLength - ring.getAuthLength();
			
			auth.setInputSize(messageLength + OtpWorker.headerLength);
			auth.initialize();
			auth.next(header);
			
			long read = 0;
			byte[] keysync = null;
			ui.verboseMessage("First pass...");
			ui.initializeProgress(messageLength);
			
			while (read < messageLength)
			{
				byte[] typeEnc = oldIn.read(1);
				auth.next(typeEnc);
				md.update(typeEnc);
				
				byte type = ByteArray.xor(encOtp.next(1), typeEnc)[0];
				read++;
				switch (type)
				{
					case 1: // normal content
						byte[] containerHeaderEnc = oldIn.read(8);
						auth.next(containerHeaderEnc);
						md.update(containerHeaderEnc);
						
						long bodyLength = ByteArray.toLong(ByteArray.xor(encOtp.next(8), containerHeaderEnc));
						
						if (bodyLength > messageLength - read - 8)
							bodyLength = messageLength - read - 8;
						
						byte[] msg = new byte[OtpWorker.blocksize];
						for (long r = 0; r < bodyLength; r += msg.length)
						{
							if (bodyLength - r < msg.length)
								msg = new byte[(int) (bodyLength - r)];
							
							oldIn.read(msg);
							auth.next(msg);
							md.update(msg);
							encOtp.next(msg.length);
							ui.updateProgress(read + r);
						}
						read += 8 + bodyLength;
						break;
					
					case 2: // compressed content
						throw new WorkResponse(6);
						// break;
						
					case 3: // normal key-sync
						
						byte[] ksParticipEnc = oldIn.read(1);
						auth.next(ksParticipEnc);
						md.update(ksParticipEnc);
						byte[] ksParticip = ByteArray.xor(ksParticipEnc, encOtp.next(1));
						
						byte[] eotpLenEnc = oldIn.read(4);
						auth.next(eotpLenEnc);
						md.update(eotpLenEnc);
						byte[] eotpLen = ByteArray.xor(eotpLenEnc, encOtp.next(4));
						
						byte[] aotpLenEnc = oldIn.read(4);
						auth.next(aotpLenEnc);
						md.update(aotpLenEnc);
						byte[] aotpLen = ByteArray.xor(aotpLenEnc, encOtp.next(4));
						
						byte[] syncE = oldIn.read(ByteArray.toInt(eotpLen) + ByteArray.toInt(aotpLen));
						auth.next(syncE);
						md.update(syncE);
						byte[] sync = ByteArray.xor(syncE, encOtp.next(syncE.length));
						
						keysync = new byte[9 + sync.length];
						System.arraycopy(ksParticip, 0, keysync, 0, 1);
						System.arraycopy(eotpLen, 0, keysync, 1, 4);
						System.arraycopy(aotpLen, 0, keysync, 5, 4);
						System.arraycopy(sync, 0, keysync, 9, sync.length);
						
						read += keysync.length;
						ui.updateProgress(read);
						break;
					
					case 4:
						throw new WorkResponse(8);
						// break;
						
					case 5:
						throw new WorkResponse(8);
						// break;
						
					default: // message padding
						byte[] padd = new byte[OtpWorker.blocksize];
						while (read < messageLength)
						{
							if (messageLength - read < padd.length)
								padd = new byte[(int) (messageLength - read)];
							
							oldIn.read(padd);
							auth.next(padd);
							md.update(padd);
							encOtp.next(padd);
							read += padd.length;
							ui.updateProgress(read);
						}
				}
			}
			ui.finishProgress();
			
			byte[] mac = auth.doFinal();
			byte[] mac2 = oldIn.read(mac.length);
			md.update(mac2);
			
			if (!Arrays.equals(mac, mac2))
				throw new WorkResponse(2);
			
			BlockPlan eEndPlan = encOtp.getPosition();
			BlockPlan aEndPlan = authOtp.getPosition();
			
			if (!ring.verifyMessage(md.digest(), eStartPlan, eEndPlan, aStartPlan, aEndPlan)[0])
				throw new WorkResponse(9);
			
			int identBytes = 3;
			if (keysync == null)
			{
				identBytes--;
				keysync = new byte[0];
			}
			
			ui.verboseMessage("Second pass...");
			oldIn.initialize();
			newIn.initialize();
			
			long newPaddingSize = messageLength - newIn.getLength() - 8 - keysync.length - identBytes;
			if (newPaddingSize < 0)
			{
				ui.warningMessage("Given message length: " + newIn.getLength() + " byte");
				ui.warningMessage("Maximal message length: " + (messageLength - 8 - keysync.length - identBytes) + " byte");
				throw new WorkResponse(5);
			}
			
			encOtp.setPosition(eStartPlan);
			oldIn.read(OtpWorker.headerLength);
			
			byte[] in1, in2, newKey;
			
			// write key-sync
			if (keysync.length > 0)
			{
				in1 = oldIn.read(1);
				in2 = new byte[] { 3 };
				newKey = ByteArray.xor(in1, in2);
				encOtp.writeNext(newKey);
				
				in1 = oldIn.read(keysync.length);
				in2 = keysync;
				newKey = ByteArray.xor(in1, in2);
				encOtp.writeNext(newKey);
			}
			
			// write message
			in1 = oldIn.read(1);
			in2 = new byte[] { 1 };
			newKey = ByteArray.xor(in1, in2);
			encOtp.writeNext(newKey);
			
			long bodyLength = newIn.getLength();
			in1 = oldIn.read(8);
			in2 = ByteArray.fromLong(bodyLength);
			newKey = ByteArray.xor(in1, in2);
			encOtp.writeNext(newKey);
			
			in1 = new byte[OtpWorker.blocksize];
			in2 = new byte[OtpWorker.blocksize];
			newKey = new byte[OtpWorker.blocksize];
			
			for (long r = 0; r < bodyLength; r += in1.length)
			{
				if (bodyLength - r < in1.length)
				{
					in1 = new byte[(int) (bodyLength - r)];
					in2 = new byte[(int) (bodyLength - r)];
					newKey = new byte[(int) (bodyLength - r)];
				}
				
				oldIn.read(in1);
				newIn.read(in2);
				ByteArray.xor(in1, in2, newKey);
				encOtp.writeNext(newKey);
			}
			
			// write padding
			in1 = oldIn.read(1);
			in2 = rng.next(1);
			
			while (in2[0] > 0 && in2[0] < 10)
				in2[0] = rng.next();
			
			newKey = ByteArray.xor(in1, in2);
			encOtp.writeNext(newKey);
			
			in1 = new byte[OtpWorker.blocksize];
			in2 = new byte[OtpWorker.blocksize];
			newKey = new byte[OtpWorker.blocksize];
			
			for (long r = 0; r < newPaddingSize; r += in1.length)
			{
				if (newPaddingSize - r < in1.length)
				{
					in1 = new byte[(int) (newPaddingSize - r)];
					in2 = new byte[(int) (newPaddingSize - r)];
					newKey = new byte[(int) (newPaddingSize - r)];
				}
				
				oldIn.read(in1);
				rng.next(in2);
				ByteArray.xor(in1, in2, newKey);
				encOtp.writeNext(newKey);
			}
			
			BlockPlan eEnd2 = encOtp.getPosition();
			
			if (!eEnd2.equalTo(eEndPlan))
				throw new WorkResponse(0);
			
			success = true;
		}
		catch (Response e)
		{
			res.add(e);
		}
		catch (NoSuchAlgorithmException e)
		{
			res.add(new WorkResponse(0, e));
		}
		finally
		{
			res.add(oldIn.finish(success));
			res.add(newIn.finish(success));
			res.add(auth.finish(success));
			res.add(encOtp.finish(success));
			res.add(authOtp.finish(success));
			res.add(ring.finish(success));
			res.add(rng.finish(success));
		}
		return res;
		
	}
	
	/**
	 * Creates a synchronisation request, if the key is suspected out of date
	 * 
	 * @param ring
	 * Settings for the key to be used, with key-id set
	 * @param out
	 * Output file for the result to be written to
	 * @param encOtp
	 * Otp used for encryption
	 * @param authOtp
	 * Otp used for authentication
	 * @param auth
	 * Authentication method
	 * @param rng
	 * Random number generator
	 * @param ui
	 * User interface
	 * @return
	 */
	public static Result createSyncReq(KeyRing ring, Outfile out, Otp encOtp, Otp authOtp, Authenticator auth, Rng rng,
			UserInterface ui)
	{
		Result res = new Result();
		boolean success = false;
		
		try
		{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			rng.initialize();
			out.initialize();
			
			ring.initialize();
			encOtp.initialize();
			authOtp.initialize();
			
			BlockPlan eStart = ring.getCurrentPlan(KeyRing.PARTICIP_ME, KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS);
			BlockPlan aStart = ring.getCurrentPlan(KeyRing.PARTICIP_ME, KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS);
			
			encOtp.setPosition(eStart.clone());
			authOtp.setPosition(aStart.clone());
			
			int syncPadd = rng.nextInt(128);
			int inputLength = syncPadd + 34;
			int paddingLength = OtpWorker.getPaddingLength(ring.getPaddingParam1(), ring.getPaddingParam2(), rng);
			
			byte[] header = new byte[OtpWorker.headerLength];
			
			byte[] syncReq = new byte[inputLength];
			
			long size = 9 + inputLength + paddingLength;
			
			if (ring.remainingBytes(eStart) < size)
				throw new WorkResponse(7);
			
			if (ring.remainingBytes(aStart) < auth.setInputSize(size + OtpWorker.headerLength))
				throw new WorkResponse(7);
			
			auth.initialize();
			
			header[0] = 2; // message format version
			System.arraycopy(ring.getKeyId(), 0, header, 1, 4);
			header[5] = (byte) ring.getKeyOwner();
			System.arraycopy(eStart.exportPlanShort(), 0, header, 6, 8);
			System.arraycopy(aStart.exportPlanShort(), 0, header, 14, 8);
			
			out.write(header);
			auth.next(header);
			md.update(header);
			
			byte[] padd = rng.next(syncPadd);
			byte[] syncPlan0e = ring.getCurrentPlan(0, KeyRing.BLOCKTYPE_E).exportPlanShort();
			byte[] syncPlan0a = ring.getCurrentPlan(0, KeyRing.BLOCKTYPE_A).exportPlanShort();
			byte[] syncPlan1e = ring.getCurrentPlan(1, KeyRing.BLOCKTYPE_E).exportPlanShort();
			byte[] syncPlan1a = ring.getCurrentPlan(1, KeyRing.BLOCKTYPE_A).exportPlanShort();
			
			syncReq[0] = 4; // sync-req
			syncReq[1] = ByteArray.fromInt(syncPadd)[3];
			
			System.arraycopy(padd, 0, syncReq, 2, syncPadd);
			
			System.arraycopy(syncPlan0e, 0, syncReq, syncPadd + 2, 8);
			System.arraycopy(syncPlan0a, 0, syncReq, syncPadd + 10, 8);
			System.arraycopy(syncPlan1e, 0, syncReq, syncPadd + 18, 8);
			System.arraycopy(syncPlan1a, 0, syncReq, syncPadd + 26, 8);
			
			byte[] srEnc = ByteArray.xor(syncReq, encOtp.next(syncReq.length));
			
			out.write(srEnc);
			auth.next(srEnc);
			md.update(srEnc);
			
			byte[] padding = rng.next(paddingLength);
			while (padding[0] > 0 && padding[0] < 10)
				padding[0] = rng.next();
			// Don't mimic other container types
			
			byte[] paddE = ByteArray.xor(padding, encOtp.next(padding.length));
			out.write(paddE);
			auth.next(paddE);
			md.update(paddE);
			
			byte[] mac = auth.doFinal();
			
			out.write(mac);
			md.update(mac);
			
			BlockPlan eEnd = encOtp.getPosition();
			BlockPlan aEnd = authOtp.getPosition();
			
			ui.verboseMessage("Message areas: " + eStart + "- " + eEnd + ", " + aStart + "- " + aEnd);
			
			if (!ring.verifyMessage(md.digest(), eStart, eEnd, aStart, aEnd)[0])
				throw new WorkResponse(0);
			
			ring.updatePlan(KeyRing.PARTICIP_ME, KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS, eEnd);
			ring.updatePlan(KeyRing.PARTICIP_ME, KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS, aEnd);
			
			success = true;
		}
		catch (Response e)
		{
			res.add(e);
		}
		catch (NoSuchAlgorithmException e)
		{
			res.add(new WorkResponse(0, e));
		}
		finally
		{
			res.add(out.finish(success));
			res.add(auth.finish(success));
			res.add(encOtp.finish(success));
			res.add(authOtp.finish(success));
			res.add(ring.finish(success));
			res.add(rng.finish(success));
		}
		return res;
	}
	
	/**
	 * Creates a synchronisation response, if the partners key is suspected out of
	 * date
	 * 
	 * @param ring
	 * Settings for the key to be used, with key-id set
	 * @param out
	 * Output file for the result to be written to
	 * @param encOtp
	 * Otp used for encryption
	 * @param authOtp
	 * Otp used for authentication
	 * @param auth
	 * Authentication method
	 * @param rng
	 * Random number generator
	 * @param ui
	 * User interface
	 * @return
	 */
	public static Result createSyncAck(KeyRing ring, Outfile out, Otp encOtp, Otp authOtp, Authenticator auth, Rng rng,
			UserInterface ui)
	{
		Result res = new Result();
		boolean success = false;
		
		try
		{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			rng.initialize();
			out.initialize();
			
			ring.initialize();
			encOtp.initialize();
			authOtp.initialize();
			
			if (!ring.keyInSync())
				throw new WorkResponse(12);
			
			BlockPlan eStart = ring.getCurrentPlan(KeyRing.PARTICIP_ME, KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS);
			BlockPlan aStart = ring.getCurrentPlan(KeyRing.PARTICIP_ME, KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS);
			
			encOtp.setPosition(eStart.clone());
			authOtp.setPosition(aStart.clone());
			
			BlockPlan[] oldPlan = ring.keyGetPartnerSync();
			
			// skip possibly dirty bytes
			BlockPlan otherEPlan = ring.getCurrentPlan(KeyRing.PARTICIP_OTHER, KeyRing.BLOCKTYPE_E);
			BlockPlan otherAPlan = ring.getCurrentPlan(KeyRing.PARTICIP_OTHER, KeyRing.BLOCKTYPE_A);
			
			ring.fastForwardPlan(otherEPlan, ring.remainingBytes(otherEPlan));
			ring.fastForwardPlan(otherAPlan, ring.remainingBytes(otherAPlan));
			ring.fillPlan(otherEPlan);
			ring.fillPlan(otherAPlan);
			ring.updatePlan(KeyRing.PARTICIP_OTHER, KeyRing.BLOCKTYPE_E, otherEPlan);
			ring.updatePlan(KeyRing.PARTICIP_OTHER, KeyRing.BLOCKTYPE_A, otherAPlan);
			
			if (oldPlan[0 | KeyRing.BLOCKTYPE_E] != null &&
					oldPlan[0 | KeyRing.BLOCKTYPE_E].greaterThan(ring.getCurrentPlan(0, KeyRing.BLOCKTYPE_E)) ||
					oldPlan[0 | KeyRing.BLOCKTYPE_A] != null &&
					oldPlan[0 | KeyRing.BLOCKTYPE_A].greaterThan(ring.getCurrentPlan(0, KeyRing.BLOCKTYPE_A)) ||
					oldPlan[1 | KeyRing.BLOCKTYPE_E] != null &&
					oldPlan[1 | KeyRing.BLOCKTYPE_E].greaterThan(ring.getCurrentPlan(1, KeyRing.BLOCKTYPE_E)) ||
					oldPlan[1 | KeyRing.BLOCKTYPE_A] != null &&
					oldPlan[1 | KeyRing.BLOCKTYPE_A].greaterThan(ring.getCurrentPlan(1, KeyRing.BLOCKTYPE_A)))
			{
				ui.warningMessage("Inconsistent key state, syncronisation not possible.");
				throw new WorkResponse(12);
			}
			
			byte[] sync0e = ring.getCurrentPlan(0, KeyRing.BLOCKTYPE_E).exportPlanBetween(oldPlan[0 | KeyRing.BLOCKTYPE_E]);
			byte[] sync0a = ring.getCurrentPlan(0, KeyRing.BLOCKTYPE_A).exportPlanBetween(oldPlan[0 | KeyRing.BLOCKTYPE_A]);
			byte[] sync1e = ring.getCurrentPlan(1, KeyRing.BLOCKTYPE_E).exportPlanBetween(oldPlan[1 | KeyRing.BLOCKTYPE_E]);
			byte[] sync1a = ring.getCurrentPlan(1, KeyRing.BLOCKTYPE_A).exportPlanBetween(oldPlan[1 | KeyRing.BLOCKTYPE_A]);
			
			byte[] sync0eLen = ByteArray.fromInt(sync0e.length);
			byte[] sync0aLen = ByteArray.fromInt(sync0a.length);
			byte[] sync1eLen = ByteArray.fromInt(sync1e.length);
			byte[] sync1aLen = ByteArray.fromInt(sync1a.length);
			
			byte[] syncSose = ring.getCurrentPlan(1 - ring.getKeyOwner(), KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS).exportPlanShort();
			byte[] syncSosa = ring.getCurrentPlan(1 - ring.getKeyOwner(), KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS).exportPlanShort();
			
			int inputLength = sync0e.length + sync0a.length + sync1e.length + sync1a.length + 37;
			int paddingLength = OtpWorker.getPaddingLength(ring.getPaddingParam1(), ring.getPaddingParam2(), rng);
			byte[] header = new byte[OtpWorker.headerLength];
			
			byte[] syncAck = new byte[inputLength];
			
			long size = 9 + inputLength + paddingLength;
			
			if (ring.remainingBytes(eStart) < size)
				throw new WorkResponse(7);
			
			if (ring.remainingBytes(aStart) < auth.setInputSize(size + OtpWorker.headerLength))
				throw new WorkResponse(7);
			
			auth.initialize();
			
			header[0] = 2; // message format version
			System.arraycopy(ring.getKeyId(), 0, header, 1, 4);
			header[5] = (byte) ring.getKeyOwner();
			System.arraycopy(eStart.exportPlanShort(), 0, header, 6, 8);
			System.arraycopy(aStart.exportPlanShort(), 0, header, 14, 8);
			
			out.write(header);
			auth.next(header);
			md.update(header);
			
			syncAck[0] = 5; // sync-ack
			System.arraycopy(ByteArray.fromInt((int) (System.currentTimeMillis() / 1000)), 0, syncAck, 1, 4);
			
			System.arraycopy(sync0eLen, 0, syncAck, 5, 4);
			System.arraycopy(sync0aLen, 0, syncAck, 9, 4);
			System.arraycopy(sync1eLen, 0, syncAck, 13, 4);
			System.arraycopy(sync1aLen, 0, syncAck, 17, 4);
			
			System.arraycopy(sync0e, 0, syncAck, 21, sync0e.length);
			System.arraycopy(sync0a, 0, syncAck, 21 + sync0e.length, sync0a.length);
			System.arraycopy(sync1e, 0, syncAck, 21 + sync0e.length + sync0a.length, sync1e.length);
			System.arraycopy(sync1a, 0, syncAck, 21 + sync0e.length + sync0a.length + sync1e.length, sync1a.length);
			
			System.arraycopy(syncSose, 0, syncAck, 21 + sync0e.length + sync0a.length + sync1e.length + sync1a.length, 8);
			System.arraycopy(syncSosa, 0, syncAck, 21 + sync0e.length + sync0a.length + sync1e.length + sync1a.length + 8, 8);
			
			byte[] saEnc = ByteArray.xor(syncAck, encOtp.next(syncAck.length));
			
			out.write(saEnc);
			auth.next(saEnc);
			md.update(saEnc);
			
			byte[] padding = rng.next(paddingLength);
			while (padding[0] > 0 && padding[0] < 10)
				padding[0] = rng.next();
			// Don't mimic other container types
			
			byte[] paddE = ByteArray.xor(padding, encOtp.next(padding.length));
			out.write(paddE);
			auth.next(paddE);
			md.update(paddE);
			
			byte[] mac = auth.doFinal();
			
			out.write(mac);
			md.update(mac);
			
			BlockPlan eEnd = encOtp.getPosition();
			BlockPlan aEnd = authOtp.getPosition();
			
			ui.verboseMessage("Message areas: " + eStart + "- " + eEnd + ", " + aStart + "- " + aEnd);
			
			if (!ring.verifyMessage(md.digest(), eStart, eEnd, aStart, aEnd)[0])
				throw new WorkResponse(0);
			
			ring.updatePlan(KeyRing.PARTICIP_ME, KeyRing.BLOCKTYPE_E | KeyRing.BLOCKTYPE_SOS, eEnd);
			ring.updatePlan(KeyRing.PARTICIP_ME, KeyRing.BLOCKTYPE_A | KeyRing.BLOCKTYPE_SOS, aEnd);
			
			ring.keySetPartnerSync(null);
			success = true;
		}
		catch (Response e)
		{
			res.add(e);
		}
		catch (NoSuchAlgorithmException e)
		{
			res.add(new WorkResponse(0, e));
		}
		finally
		{
			res.add(out.finish(success));
			res.add(auth.finish(success));
			res.add(encOtp.finish(success));
			res.add(authOtp.finish(success));
			res.add(ring.finish(success));
			res.add(rng.finish(success));
		}
		return res;
	}
	
	private static void cryptWorkload(Long length, int direction, Infile in, Outfile out, Authenticator auth, Otp otp,
			UserInterface ui, MessageDigest md) throws Response
	{
		long i = 0;
		int block_size = OtpWorker.blocksize;
		byte[] p = new byte[block_size];
		byte[] e = new byte[block_size];
		byte[] o = new byte[block_size];
		
		if (length == null)
			length = in.getLength();
		
		ui.initializeProgress(length);
		
		while (i < length)
		{
			ui.updateProgress(i);
			
			if (i + block_size > length)
			{
				block_size = (int) (length - i);
				p = new byte[block_size];
				o = new byte[block_size];
				e = new byte[block_size];
			}
			
			in.read(p);
			otp.next(o);
			ByteArray.xor(p, o, e);
			
			auth.next(direction == OtpWorker.ACTION_DECRYPT ? p : e);
			if (md != null)
				md.update(direction == OtpWorker.ACTION_DECRYPT ? p : e);
			out.write(e);
			i += block_size;
		}
		ui.finishProgress();
	}
	
	private static int getPaddingLength(int param1, int param2, Rng rng) throws RngResponse
	{
		double sig = ((double) param2) / 100; // distribution
		
		// mode: e^(my - sig²)
		// double my = StrictMath.log((double) param1) + (sig * sig);
		
		// median: e^my
		double my = StrictMath.log((double) param1);
		
		// mean: e^(my + 1/2 sig²)
		// double my = StrictMath.log((double) param1) - (sig * sig / 2);
		
		double u1 = rng.nextDouble();
		double u2 = rng.nextDouble();
		
		return (int) Math.ceil(StrictMath.exp(my + sig * StrictMath.sqrt(-2 * StrictMath.log(u1)) *
				StrictMath.sin(2 * Math.PI * u2)));
	}
}
