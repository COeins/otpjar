package otp.response;

public class KeyringResponse extends Response
{
	private static final long serialVersionUID = 1L;
	private String[] texts = new String[] {
			"Incorrect key ring initialization", // 0
			"Key not found, please import the required key or specify the containing key ring.",
			"Keyring file read error",
			"Keyring file corrupt",
			"Keyring file write error, please check if the directory exists and is not write protected.",
			"Keyring file version unsupported", // 5
			"Could not decrypt key ring. Either you entered a wrong passphrase, or this file might be corrupt.",
			"OTP key file not found", "New passphrase too short", "Block type or address error",
			"Specified block id not assigned", // 10
	};
	
	public KeyringResponse(boolean success)
	{
		super(success, -1, null);
		super.errorMessages = texts;
	}
	
	public KeyringResponse(int errorCode)
	{
		super(false, errorCode, null);
		super.errorMessages = texts;
		if (errorCode == 6)
			super.setExitCode(3);
	}
	
	public KeyringResponse(int errorCode, Throwable cause)
	{
		super(false, errorCode, cause);
		super.errorMessages = texts;
		if (errorCode == 6)
			super.setExitCode(3);
	}
}
