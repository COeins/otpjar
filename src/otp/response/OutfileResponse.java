package otp.response;

public class OutfileResponse extends Response
{
	
	private static final long serialVersionUID = 1L;
	private String[] texts = new String[] { "Incorrect outfile initialization",
			"Output file/stream could not be created", "Write error", "Cancelled by user" };
	
	public OutfileResponse(boolean success)
	{
		super(success, -1, null);
		super.errorMessages = texts;
	}
	
	public OutfileResponse(int errorCode)
	{
		super(false, errorCode, null);
		super.errorMessages = texts;
	}
	
	public OutfileResponse(int errorCode, Throwable cause)
	{
		super(false, errorCode, cause);
		super.errorMessages = texts;
	}
}
