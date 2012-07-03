package otp.response;

public class CipherResponse extends Response
{
	private static final long serialVersionUID = 1L;
	private String[] texts = new String[] { "Incorrect initialization", "Internal error", "Incorrect key size",
			"Incorrect direction", "Incorrect operation mode" };
	
	public CipherResponse(boolean success)
	{
		super(success, -1, null);
		super.errorMessages = texts;
	}
	
	public CipherResponse(int errorCode)
	{
		super(false, errorCode, null);
		super.errorMessages = texts;
	}
	
	public CipherResponse(int errorCode, Throwable cause)
	{
		super(false, errorCode, cause);
		super.errorMessages = texts;
	}
}
