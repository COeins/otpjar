package otp.response;

public class UiResponse extends Response
{
	private static final long serialVersionUID = 1L;
	private String[] texts = new String[] { "Incorrect initialization", "Cannot read from stdin.",
			"Disabled interactivity", "Encoding Error", "Console read error" };
	
	public UiResponse(boolean success)
	{
		super(success, -1, null);
		super.errorMessages = texts;
	}
	
	public UiResponse(int errorCode)
	{
		super(false, errorCode, null);
		super.errorMessages = texts;
		if (errorCode == 2)
			super.setExitCode(2);
	}
	
	public UiResponse(int errorCode, Throwable cause)
	{
		super(false, errorCode, cause);
		super.errorMessages = texts;
		if (errorCode == 2)
			super.setExitCode(2);
	}
}
