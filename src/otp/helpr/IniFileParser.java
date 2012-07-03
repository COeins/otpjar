package otp.helpr;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class IniFileParser
{
	private Map<String, Map<String, String>> values;
	private String section;
	
	public IniFileParser()
	{
		this.values = new TreeMap<String, Map<String, String>>();
		this.section = "";
	}
	
	public IniFileParser(String input) throws ParseException
	{
		this.values = new TreeMap<String, Map<String, String>>();
		this.section = "";
		this.parse(input);
	}
	
	/**
	 * Reads all ini data from a given string
	 * 
	 * @param input
	 * @throws ParseException
	 */
	public void parse(String input) throws ParseException
	{
		
		String[] lines = input.split("[ \\t\\x0B\\x00]*([\\r\\n]+[ \\t\\x0B\\x00]*)+");
		String[] kv;
		
		for (int line = 0; line < lines.length; line++)
		{
			if (lines[line].charAt(0) == '#' || lines[line] == "")
			{
				// comment
			}
			else if (lines[line].charAt(0) == '[' && lines[line].charAt(lines[line].length() - 1) == ']')
			{
				this.section = lines[line].substring(1, lines[line].length() - 1);
			}
			else if (lines[line].contains("="))
			{
				kv = lines[line].split("=", 2);
				this.setValue(this.section, kv[0], kv[1]);
			}
			else
			{
				throw new ParseException("Syntax Error", line + 1);
			}
		}
	}
	
	/**
	 * Exports all stored data to a ini file string
	 * 
	 * @return
	 */
	public String export()
	{
		if (this.values.isEmpty())
			return "";
		
		StringBuilder output = new StringBuilder();
		
		for (String sect : this.values.keySet())
		{
			if (!this.values.get(sect).isEmpty())
			{
				if (sect != "")
				{
					output.append("[" + sect + "]\n");
				}
				
				for (String key : this.values.get(sect).keySet())
				{
					String val = this.values.get(sect).get(key);
					
					if (val != null)
					{
						output.append(key + "=" + val + "\n");
					}
				}
			}
		}
		return output.toString();
	}
	
	/**
	 * Cleares all stored data
	 */
	public void reset()
	{
		this.values = new HashMap<String, Map<String, String>>();
		this.section = "";
	}
	
	/**
	 * Returns the specified value as String
	 * 
	 * @param section
	 * @param key
	 * @return
	 */
	public String getValueString(String section, String key)
	{
		if (section == null)
			section = "";
		
		if (!this.values.containsKey(section))
			return null;
		
		return this.values.get(section).get(key);
	}
	
	/**
	 * Returns the specified value as boolean
	 * 
	 * @param section
	 * @param key
	 * @return
	 */
	public boolean getValueBool(String section, String key)
	{
		String val = this.getValueString(section, key);
		
		if (val == null)
			return false;
		else if (val.equals("true"))
			return true;
		else
			return false;
	}
	
	/**
	 * Returns the specified value as int
	 * 
	 * @param section
	 * @param key
	 * @return
	 */
	public int getValueInt(String section, String key)
	{
		String val = this.getValueString(section, key);
		
		if (val == null)
			return 0;
		else
			return new Integer(val);
	}
	
	/**
	 * Returns the specified value as long
	 * 
	 * @param section
	 * @param key
	 * @return
	 */
	public long getValueLong(String section, String key)
	{
		String val = this.getValueString(section, key);
		
		if (val == null)
			return 0;
		else
			return new Long(val);
	}
	
	/**
	 * Returns the specified value as byte array
	 * 
	 * @param section
	 * @param key
	 * @return
	 */
	public byte[] getValueBytes(String section, String key)
	{
		String val = this.getValueString(section, key);
		
		if (val == null)
			return null;
		else
			return ByteArray.fromRadix64(val);
	}
	
	/**
	 * Returns a set of all section headings
	 * 
	 * @return
	 */
	public Set<String> getSections()
	{
		return this.values.keySet();
	}
	
	/**
	 * Removes a certain value from the stored data
	 * 
	 * @param section
	 * @param key
	 */
	public void removeValue(String section, String key)
	{
		if (this.values.containsKey(section))
		{
			this.values.get(section).remove(key);
		}
	}
	
	/**
	 * Updates or addes a certain value
	 * 
	 * @param section
	 * @param key
	 * @param value
	 */
	public void setValue(String section, String key, String value)
	{
		if (section == null)
			section = "";
		
		if (section == "" && key == "keyRing")
			throw new RuntimeException("DEBUG");
		
		if (!this.values.containsKey(section))
			this.values.put(section, new HashMap<String, String>());
		
		this.values.get(section).put(key, value);
	}
	
	/**
	 * Updates or addes a certain value
	 * 
	 * @param section
	 * @param key
	 * @param value
	 */
	public void setValue(String section, String key, boolean value)
	{
		this.setValue(section, key, value ? "true" : "false");
	}
	
	/**
	 * Updates or addes a certain value
	 * 
	 * @param section
	 * @param key
	 * @param value
	 */
	public void setValue(String section, String key, int value)
	{
		this.setValue(section, key, new Integer(value).toString());
	}
	
	/**
	 * Updates or addes a certain value
	 * 
	 * @param section
	 * @param key
	 * @param value
	 */
	public void setValue(String section, String key, long value)
	{
		this.setValue(section, key, new Long(value).toString());
	}
	
	/**
	 * Updates or addes a certain value
	 * 
	 * @param section
	 * @param key
	 * @param value
	 */
	public void setValue(String section, String key, byte[] value)
	{
		this.setValue(section, key, ByteArray.toRadix64(value, 0));
	}
}
