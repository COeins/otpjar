package otp.response;

public abstract class Response extends Throwable
{
	private static final long serialVersionUID = 1L;
	private boolean success = false;
	private int errorcode = -1;
	private int exitcode = 0;
	
	protected String[] errorMessages = {};
	
	public Response(boolean success, int errorCode, Throwable cause)
	{
		this.success = success;
		this.errorcode = errorCode;
		if (!success)
			this.exitcode = 255;
		if (!success && cause != null)
			this.initCause(cause);
	}
	
	public boolean getSuccess()
	{
		return this.success;
	}
	
	public int getErrorCode()
	{
		return this.errorcode;
	}
	
	@Override
	public String getMessage()
	{
		if (this.errorcode == -1)
			return "OK";
		else
			return this.generateErrorMsg(this.errorcode);
	}
	
	public int getExitCode()
	{
		return this.exitcode;
	}
	
	protected void setExitCode(int code)
	{
		// 0 => ok
		// 1 => message
		// 2 => question
		// 3 => passphrase
		// 4 => own key out of sync
		// 5 => partner out of sync
		// 6 => deny message to long
		this.exitcode = code;
	}
	
	protected String generateErrorMsg(int code)
	{
		try
		{
			return this.errorMessages[code];
		}
		catch (ArrayIndexOutOfBoundsException e)
		{
			return "Unknown " + this.getClass() + ": " + code;
		}
	}
}
