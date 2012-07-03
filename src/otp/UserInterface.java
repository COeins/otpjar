package otp;

import otp.response.UiResponse;

public abstract class UserInterface
{
	
	/**
	 * Initializes the progress-display.
	 * 
	 * @param max
	 * The maximum number the progress will reach
	 */
	public abstract void initializeProgress(long max);
	
	/**
	 * Updates a progress-display. Needs to be initialized first.
	 * 
	 * @param current
	 * The current number the progress has reached
	 */
	public abstract void updateProgress(long current);
	
	/**
	 * Finishes a progress-display. Needs to be initialized first.
	 */
	public abstract void finishProgress();
	
	/**
	 * Asks the user for the passphrase for a given key-id. Passphrase may be
	 * cached as long as the key-id remains unchanged across calls.
	 * 
	 * @param keyId
	 * The key the passphrase should be used for
	 * @return The entered passphrase
	 * @throws UiResponse
	 */
	public abstract byte[] getPassphrase(String keyId) throws UiResponse;
	
	/**
	 * Asks the user for a new passphrase for the given key-id. Cached passphrases
	 * are not used. The user is asked twice to confirm correct input.
	 * 
	 * @param keyId
	 * The key the passphrase should be used for
	 * @return The entered passphrase
	 * @throws UiResponse
	 */
	public abstract byte[] getNewPassphrase(String keyId) throws UiResponse;
	
	/**
	 * Asks a Yes/No question. A default answer ne be specified.
	 * 
	 * @param prompt
	 * The question to be asked
	 * @param def
	 * The default answer or NULL
	 * @return The answer or NULL if the user cancelled
	 * @throws UiResponse
	 */
	public abstract Boolean promptYN(String prompt, Boolean def) throws UiResponse;
	
	/**
	 * Prompt the user for a numeric input.
	 * 
	 * @param prompt
	 * The prompt string
	 * @param def
	 * The default answer or NULL
	 * @return The answer or NULL if the user cancelled
	 * @throws UiResponse
	 */
	public Long promptNumber(String prompt, Long def) throws UiResponse
	{
		return this.promptNumber(prompt, def, null, null);
	}
	
	/**
	 * Prompt the user for a numeric input.
	 * 
	 * @param prompt
	 * The prompt string
	 * @param def
	 * The default answer or NULL
	 * @param min
	 * Minimal valid value (incl.), may be null for undefined
	 * @param max
	 * Maximal valid value (incl.), may be null for undefined
	 * @return The answer or NULL if the user cancelled
	 * @throws UiResponse
	 */
	public abstract Long promptNumber(String prompt, Long def, Long min, Long max) throws UiResponse;
	
	/**
	 * Prompts the user for a string input.
	 * 
	 * @param prompt
	 * The prompt string
	 * @param def
	 * The default answer or NULL
	 * @return The answer or NULL if the user cancelled.
	 * @throws UiResponse
	 */
	public abstract String promptStr(String prompt, String def) throws UiResponse;
	
	/**
	 * Outputs a normal Message to the user.
	 * 
	 * @param message
	 * The message to be output
	 */
	public abstract void message(String message);
	
	/**
	 * Outputs a verbose message to the user. Normally verbose messages are not
	 * shown, but the user me choose to get them displayed.
	 * 
	 * @param message
	 * The message to be output
	 */
	public abstract void verboseMessage(String message);
	
	/**
	 * Outputs a warning message to the user. Warning messages cannot be
	 * suppressed.
	 * 
	 * @param message
	 * The message to be output
	 */
	public abstract void warningMessage(String message);
	
}
