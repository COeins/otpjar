package otp.response;

public class OtpResponse extends Response
{
	
	private static final long serialVersionUID = 1L;
	private String[] texts = new String[] { "Incorrect OTP initialization", "OTP read error", "OTP capacity exceeded",
			"OTP write error", "OTP file not found", "OTP block error" // 5
	};
	
	public OtpResponse(boolean success)
	{
		super(success, -1, null);
		super.errorMessages = texts;
	}
	
	public OtpResponse(int errorCode)
	{
		super(false, errorCode, null);
		super.errorMessages = texts;
	}
	
	public OtpResponse(int errorCode, Throwable cause)
	{
		super(false, errorCode, cause);
		super.errorMessages = texts;
	}
}
