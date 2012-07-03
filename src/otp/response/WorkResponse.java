package otp.response;

public class WorkResponse extends Response
{
	private static final long serialVersionUID = 1L;
	private String[] texts = new String[] { "Internal error", "Unsupported message format",
			"Incorrect MAC",
			"Input file corrupted",
			"Canceled by user",
			"New message to large for selected key segment", // 5
			"Input format not supported",
			"Not enough capacity in current OTP window",
			"Modification of key-sync messages not supported",
			"Message uses inconsistent OTP blocks, please check if your key is out of sync!", // 9
			"Key-sync block in normal message", // 10
			"Key-sync message inconsistent. Processing cancelled",
			"Key is temporarily deactivated, because it is out of sync! To resync, generate a syncronisation request.", // 12
			"The senders key is out of sync. Please send synchronisation message as soon as possible.", // 13
			"This key-sync message has already been processed.", "Key synced successfully.", // 15
			"Key-sync message is too old. Please check system date or request new sync." };
	
	public WorkResponse(boolean success)
	{
		super(success, -1, null);
		super.errorMessages = texts;
	}
	
	public WorkResponse(int errorCode)
	{
		super(false, errorCode, null);
		super.errorMessages = texts;
		if (errorCode == 12)
			super.setExitCode(4);
		else if (errorCode == 13)
			super.setExitCode(5);
		else if (errorCode == 5)
			super.setExitCode(6);
	}
	
	public WorkResponse(int errorCode, Throwable cause)
	{
		super(false, errorCode, cause);
		super.errorMessages = texts;
		if (errorCode == 12)
			super.setExitCode(4);
		else if (errorCode == 13)
			super.setExitCode(5);
	}
	
	public WorkResponse(boolean success, int messageCode)
	{
		super(success, messageCode, null);
		super.errorMessages = texts;
		if (messageCode == 12)
			super.setExitCode(4);
		else if (messageCode == 13)
			super.setExitCode(5);
		else if (messageCode == 15)
			super.setExitCode(1);
	}
}
