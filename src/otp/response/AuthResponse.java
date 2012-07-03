package otp.response;

public class AuthResponse extends Response
{
	private static final long serialVersionUID = 1L;
	private String[] texts = new String[] { "Incorrect initialization", "Auth key error", "Incorrect MAC" };
	
	public AuthResponse(boolean success)
	{
		super(success, -1, null);
		super.errorMessages = texts;
	}
	
	public AuthResponse(int errorCode)
	{
		super(false, errorCode, null);
		super.errorMessages = texts;
	}
	
	public AuthResponse(int errorCode, Throwable cause)
	{
		super(false, errorCode, cause);
		super.errorMessages = texts;
	}
}
