package otp.response;

public class InfileResponse extends Response
{
	private static final long serialVersionUID = 1L;
	private String[] texts = new String[] { "Incorrect infile initialization", "Input file/stream not found",
			"Read error", "Unexpected input file format", };
	
	public InfileResponse(boolean success)
	{
		super(success, -1, null);
		super.errorMessages = texts;
	}
	
	public InfileResponse(int errorCode)
	{
		super(false, errorCode, null);
		super.errorMessages = texts;
	}
	
	public InfileResponse(int errorCode, Throwable cause)
	{
		super(false, errorCode, cause);
		super.errorMessages = texts;
	}
}
