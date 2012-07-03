import java.io.File;
import java.io.RandomAccessFile;
import java.util.Arrays;

import otp.Infile;
import otp.Outfile;
import otp.Result;
import otp.Rng;
import otp.UserInterface;
import otp.helpr.BlockAssignList;
import otp.helpr.BlockPlan;
import otp.helpr.ByteArray;
import otp.impl.BaInfile;
import otp.impl.BaOutfile;
import otp.impl.RealKeyRing;
import otp.impl.RealOtp;
import otp.impl.TestInfile;
import otp.impl.TestOutfile;
import otp.impl.TestRng;
import otp.impl.TestUi;
import otp.response.Response;
import otp.response.WorkResponse;

public class OtpTest
{
	
	public static void main(String[] args)
	{
		
		TestUi ui = new TestUi(false, false, false);
		
		int start = (int) (Math.random() * 32000);
		// int[] runs = new int[] {2216, 2220, 2224, 2233};
		
		for (int run = start; run < start + 64; run++)
		// for (int run :runs)
		{
			int send = 0;
			System.out.println("STARTING TEST RUN " + run);
			
			Rng rng = new TestRng(4, run);
			
			RealKeyRing keyring;
			String key = "08090a0b";
			String[] rings = new String[] { "33333330", "33333331" };
			int part = 0;
			Result res;
			
			File f = new File("/tmp/keys.ini");
			if (f.exists())
				f.delete();
			f = new File("/tmp/33333330.set");
			if (f.exists())
				f.delete();
			f = new File("/tmp/33333331.set");
			if (f.exists())
				f.delete();
			f = new File("/tmp/08090a0b.key");
			if (f.exists())
				f.delete();
			f = new File("/tmp/08090a0b.pad");
			if (f.exists())
				f.delete();
			f = new File("/tmp/otp0.pad");
			if (f.exists())
				f.delete();
			f = new File("/tmp/otp1.pad");
			if (f.exists())
				f.delete();
			
			try
			{
				System.out.print("\n GENERATING: ");
				// generate new key
				keyring = new RealKeyRing(rng, ui);
				keyring.selectKeyRing(rings[0]);
				keyring.setBasePath("/tmp");
				keyring.overwritePath("otp0.pad");
				
				res = OtpCmdLine.generateKey(ui, keyring, rng);
				if (!res.getSuccess())
					throw res.getErrors().get(0);
				System.out.print(".");
				
				// export key
				keyring = new RealKeyRing(rng, ui);
				keyring.selectKeyRing(rings[0]);
				keyring.setBasePath("/tmp");
				
				res = OtpCmdLine.exportKey(ui, keyring, key, "/tmp", rng);
				if (!res.getSuccess())
					throw res.getErrors().get(0);
				System.out.print(".");
				
				// import key
				keyring = new RealKeyRing(rng, ui);
				keyring.selectKeyRing(rings[1]);
				keyring.setBasePath("/tmp");
				keyring.overwritePath("otp1.pad");
				
				res = OtpCmdLine.importKey(ui, keyring, "/tmp/08090a0b.key", rng);
				if (!res.getSuccess())
					throw res.getErrors().get(0);
				System.out.print(".");
				
				System.out.print("\n SENDING (" + part + "): ");
				int rate = 30 + rng.nextInt(50);
				boolean success = false;
				byte[] oldkey = null;
				byte[] oldmsg = null;
				int oldsize = 0;
				byte[] curmsg = null;
				int cursize = 0;
				while (true)
				{
					ui.clearCache();
					
					try
					{
						int size = rng.nextInt(4 * 1024) + 1;
						ui.verboseMessage("Message size: " + size);
						// encrypt file
						Infile inc = new TestInfile(size, 32);
						BaOutfile oute = new BaOutfile();
						keyring = new RealKeyRing(rng, ui);
						keyring.setBasePath("/tmp");
						keyring.selectKeyRing(rings[part]);
						
						res = OtpCmdLine.encrypt(ui, keyring, key, inc, oute, rng.nextInt(100) < 50, rng);
						if (!res.getSuccess())
							throw res.getErrors().get(0);
						send++;
						
						if (oldmsg == null || rng.nextInt(100) < rate)
						{
							curmsg = oute.getContent();
							cursize = size;
							System.out.print(".");
						}
						else
						{
							curmsg = oldmsg;
							cursize = oldsize;
							System.out.print(",");
						}
						
						if (oldmsg == null || rng.nextInt(100) < 30)
						{
							oldmsg = oute.getContent();
							oldsize = size;
							System.out.print("'");
						}
						
						// decrypt file
						Infile ine = new BaInfile(curmsg);
						Outfile outc = new TestOutfile(cursize, 32);
						keyring = new RealKeyRing(rng, ui);
						keyring.selectKeyRing(rings[1 - part]);
						keyring.setBasePath("/tmp");
						
						res = OtpCmdLine.decrypt(ui, keyring, ine, outc, rng);
						if (!res.getSuccess())
							throw res.getErrors().get(0);
						success = true;
						
						// Modify-key
						// if (rng.nextInt(100) < 30)
						// {
						// // decrypt file
						// Infile in2 = new TestInfile(size + 10, 42);
						// keyring = new RealKeyRing(rng, ui);
						// keyring.selectKeyRing(rings[1 - part]);
						// keyring.setBasePath("/tmp");
						//
						// res = OtpCmdLine.modifyKey(ui, keyring, ine, in2, rng);
						// if (!res.getSuccess())
						// throw res.getErrors().get(0);
						// System.out.print(">");
						// recvd++;
						//
						// // decrypt file
						// Outfile out2 = new TestOutfile(size + 10, 42);
						// keyring = new RealKeyRing(rng, ui);
						// keyring.selectKeyRing(rings[1 - part]);
						// keyring.setBasePath("/tmp");
						//
						// res = OtpCmdLine.decrypt(ui, keyring, ine, out2, rng);
						// if (!res.getSuccess())
						// throw res.getErrors().get(0);
						// System.out.print(":");
						// recvd++;
						// }
						
					}
					catch (WorkResponse wr)
					{
						if (wr.getErrorCode() == 7 && success)
						{
							ui.clearCache();
							
							// switching sides...
							part = 1 - part;
							success = false;
							
							// backup key
							if (part == 0 && (oldkey == null || rng.nextInt(100) < 30))
							{
								f = new File("/tmp/33333330.set");
								try
								{
									RandomAccessFile rf = new RandomAccessFile(f, "r");
									oldkey = new byte[(int) rf.length()];
									rf.read(oldkey);
									rf.close();
									System.out.print("+");
								}
								catch (Exception e)
								{
									oldkey = null;
									System.err.print("+");
								}
							}
							// restore backup
							else if (oldkey != null && rng.nextInt(100) < 10)
							{
								f = new File("/tmp/33333330.set");
								try
								{
									RandomAccessFile rf = new RandomAccessFile(f, "rwd");
									rf.setLength(oldkey.length);
									rf.seek(0);
									rf.write(oldkey);
									rf.close();
									System.out.print("<");
								}
								catch (Exception e)
								{
								}
							}
							
						}
						// my key is out of sync
						else if (wr.getErrorCode() == 9 || wr.getErrorCode() == 12)
						{
							// wr.printStackTrace();
							System.out.print("\n REQUESTING SYNC: ");
							ui.clearCache();
							// send sync-request
							BaOutfile oute = new BaOutfile();
							keyring = new RealKeyRing(rng, ui);
							keyring.setBasePath("/tmp");
							keyring.selectKeyRing(rings[0]);
							
							res = OtpCmdLine.syncReq(ui, keyring, key, oute, false, rng);
							if (!res.getSuccess())
								throw res.getErrors().get(0);
							
							Infile ine = new BaInfile(oute.getContent());
							BaOutfile outc = new BaOutfile();
							keyring = new RealKeyRing(rng, ui);
							keyring.selectKeyRing(rings[1]);
							keyring.setBasePath("/tmp");
							
							res = OtpCmdLine.decrypt(ui, keyring, ine, outc, rng);
							if (!res.getSuccess())
							{
								Response r = res.getErrors().get(0);
								if (!(r instanceof WorkResponse) || r.getErrorCode() != 13)
									throw r;
							}
							
							System.out.print("-");
							ui.clearCache();
							
							// send sync-message
							oute = new BaOutfile();
							keyring = new RealKeyRing(rng, ui);
							keyring.setBasePath("/tmp");
							keyring.selectKeyRing(rings[1]);
							
							res = OtpCmdLine.syncAck(ui, keyring, key, oute, false, rng);
							if (!res.getSuccess())
								throw res.getErrors().get(0);
							
							ine = new BaInfile(oute.getContent());
							outc = new BaOutfile();
							keyring = new RealKeyRing(rng, ui);
							keyring.selectKeyRing(rings[0]);
							keyring.setBasePath("/tmp");
							
							res = OtpCmdLine.decrypt(ui, keyring, ine, outc, rng);
							if (!res.getSuccess())
								throw res.getErrors().get(0);
							
							System.out.print(">");
							
							success = true;
							oldmsg = null;
						}
						// their key is out of sync
						else if (wr.getErrorCode() == 13)
						{
							System.out.print("\n SENDING SYNC: ");
							ui.clearCache();
							// send sync-message
							BaOutfile oute = new BaOutfile();
							keyring = new RealKeyRing(rng, ui);
							keyring.setBasePath("/tmp");
							keyring.selectKeyRing(rings[1]);
							
							res = OtpCmdLine.syncAck(ui, keyring, key, oute, false, rng);
							if (!res.getSuccess())
								throw res.getErrors().get(0);
							
							Infile ine = new BaInfile(oute.getContent());
							Outfile outc = new BaOutfile();
							keyring = new RealKeyRing(rng, ui);
							keyring.selectKeyRing(rings[0]);
							keyring.setBasePath("/tmp");
							
							res = OtpCmdLine.decrypt(ui, keyring, ine, outc, rng);
							if (!res.getSuccess())
								throw res.getErrors().get(0);
							
							System.out.print(">");
							
							success = true;
							oldmsg = null;
						}
						else
							throw wr;
						System.out.print("\n SENDING (" + part + "): ");
					}
					
				}
			}
			catch (Response r)
			{
				if (r instanceof WorkResponse && r.getErrorCode() == 7)
				{
					System.out.println("\n" + r.getMessage());
				}
				else
				{
					ui.message("");
					// print infos
					keyring = new RealKeyRing(rng, ui);
					keyring.setBasePath("/tmp");
					keyring.selectKeyRing(rings[part]);
					OtpCmdLine.keyInfo(ui, keyring, key);
					
					keyring = new RealKeyRing(rng, ui);
					keyring.setBasePath("/tmp");
					keyring.selectKeyRing(rings[1 - part]);
					OtpCmdLine.keyInfo(ui, keyring, key);
					
					System.out.println("\n");
					while (r.getCause() instanceof Response)
					{
						ui.warningMessage("\n" + r.getMessage());
						r = (Response) r.getCause();
					}
					ui.printCache();
					r.printStackTrace();
					
				}
			}
			System.out.println("\nTEST RUN " + run + " ENDED");
			System.out.println(" " + send + " messages sent and recieved.");
			// break;
		}
	}
	
	/**
	 * Can be used to verify both participants otps are equal
	 * 
	 * @param rng
	 * @param ui
	 * @param rings
	 * @param keyId
	 * @throws Response
	 */
	public static void compareKeys(Rng rng, UserInterface ui, String[] rings, String keyId) throws Response
	{
		
		RealKeyRing keyring0 = new RealKeyRing(rng, ui);
		RealKeyRing keyring1 = new RealKeyRing(rng, ui);
		RealOtp otp0 = new RealOtp(keyring0, ui);
		RealOtp otp1 = new RealOtp(keyring1, ui);
		
		try
		{
			System.out.print("\n COMPRATING KEYS...");
			keyring0.setBasePath("/tmp");
			keyring0.selectKeyRing(rings[0]);
			keyring0.selectKey(keyId);
			keyring0.initialize();
			
			keyring1.setBasePath("/tmp");
			keyring1.selectKeyRing(rings[1]);
			keyring1.selectKey(keyId);
			keyring1.initialize();
			
			BlockAssignList bab = new BlockAssignList(new BlockAssignList[0]);
			for (int i = 0; i < keyring0.getBlockCount(); i++)
			{
				bab.addBlock(i);
			}
			
			BlockPlan p0 = new BlockPlan(bab);
			BlockPlan p1 = new BlockPlan(bab);
			otp0.setPosition(p0);
			otp1.setPosition(p1);
			
			otp0.initialize();
			otp1.initialize();
			
			int block = 64;
			byte[] in0 = new byte[64];
			byte[] in1 = new byte[64];
			
			long read = 0;
			long max = keyring0.remainingBytes(p0);
			
			while (read < max)
			{
				if (max - read < block)
				{
					block = (int) (max - read);
					in0 = new byte[block];
					in1 = new byte[block];
				}
				
				otp0.next(in0);
				otp1.next(in1);
				if (!Arrays.equals(in0, in1))
				{
					System.err.println("ERROR " + read);
					System.err.println(" otp0: " + ByteArray.toHex(in0, " "));
					System.err.println(" otp1: " + ByteArray.toHex(in1, " "));
				}
				read += block;
			}
		}
		catch (Response r1)
		{
			throw r1;
		}
		catch (Exception e)
		{
			throw new WorkResponse(0, e);
		}
		finally
		{
			otp0.finish(true);
			otp1.finish(true);
			keyring0.finish(true);
			keyring1.finish(true);
		}
	}
}
