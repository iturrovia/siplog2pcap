package siplog2pcap;

/**
 * LogFrameParser interface implements the methods to parse a LogFrame
 */
public interface LogFrameParser {

	/* INSTANCE METHODS */

	/**	Parses one line to check whether it is a header line or not, so:
	 * - If it is the header line of a log frame, it parses it and returns the parsed data in a non-null T object
	 * - If not, then it returns null
	 *	@param	line
	 *	@return	the resulting LogFrame (or null if not a header line) */
	public LogFrame parseHeaderLine(String line);

	/**	Postprocesses the input LogFrame, reading data from logLines and updating
	 *	other instance variables (at least sipLines)
	 *	@param	logFrame */
	public void postProcessLogFrame(LogFrame logFrame);
	
}