package otp;

import java.util.LinkedList;
import java.util.List;

import otp.response.Response;

public class Result
{
	private List<Response> responses;
	private List<Response> errors;
	private boolean success = true;
	private int exitCode = 0;
	
	/**
	 * Creates a new Result object.
	 */
	public Result()
	{
		this.responses = new LinkedList<Response>();
		this.errors = new LinkedList<Response>();
	}
	
	/**
	 * Creates a new Result an adds one response
	 * 
	 * @param r
	 */
	public Result(Response r)
	{
		this.responses = new LinkedList<Response>();
		this.errors = new LinkedList<Response>();
		this.add(r);
	}
	
	/**
	 * Adds a new response to the Result. Updates success and errors accordingly.
	 * 
	 * @param r
	 * The response object to be added
	 */
	public void add(Response r)
	{
		if (r == null)
			return;
		
		this.responses.add(r);
		
		if (r.getExitCode() > 0 || !r.getSuccess())
		{
			this.success &= r.getSuccess();
			this.exitCode = Math.max(r.getExitCode(), this.exitCode);
			this.errors.add(r);
		}
	}
	
	/**
	 * Returns success of the operation. An operation is considered successful all
	 * responses are free of errors.
	 * 
	 * @return Success of the Operation
	 */
	public boolean getSuccess()
	{
		return this.success;
	}
	
	/**
	 * Return the largest exit code of all containing responses
	 * 
	 * @return Exit Code
	 */
	public int getExitCode()
	{
		return this.exitCode;
	}
	
	/**
	 * Returns a List of all Responses.
	 * 
	 * @return All responses
	 */
	public List<Response> getResponses()
	{
		return this.responses;
	}
	
	/**
	 * Returns a List of all Responses that contain errors or nonzero exit codes.
	 * 
	 * @return All responses containing errors.
	 */
	public List<Response> getErrors()
	{
		return this.errors;
	}
	
}
