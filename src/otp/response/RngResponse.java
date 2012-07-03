package otp.response;

public class RngResponse extends Response
{
	private static final long serialVersionUID = 1L;
	private String[] texts = new String[] { "Incorrect RNG initialization", "Random number file read error" };
	
	public RngResponse(boolean success)
	{
		super(success, -1, null);
		super.errorMessages = texts;
	}
	
	public RngResponse(int errorCode)
	{
		super(false, errorCode, null);
		super.errorMessages = texts;
	}
	
	public RngResponse(int errorCode, Throwable cause)
	{
		super(false, errorCode, cause);
		super.errorMessages = texts;
	}
}
