package siplog2pcap.parsers;

import siplog2pcap.LogFrame;
import siplog2pcap.LogFrameParser;
import java.util.ArrayList;
import java.lang.StringBuilder;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.TimeZone;
import java.util.HashMap;
import java.util.List;
import java.util.Iterator;
import java.net.InetAddress;

/**
 * ApktLog class is a collection of tools to parse APKT logs
 */
public class AcmePacket implements LogFrameParser {
	
	private static final String HEADER_LINE_REGEX = "([a-zA-Z]{3})\\s+([0-9]{1,2}) ([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2}).([0-9]{3}) (.*)";
	private static int CAPTURE_GROUP_MONTH = 1;
	private static int CAPTURE_GROUP_DAY = 2;
	private static int CAPTURE_GROUP_HOUR = 3;
	private static int CAPTURE_GROUP_MINUTES = 4;
	private static int CAPTURE_GROUP_SECONDS = 5;
	private static int CAPTURE_GROUP_MILISECONDS = 6;
	private static int CAPTURE_GROUP_GENERICDATA = 7;
	private static final Pattern HEADER_LINE_PATTERN = Pattern.compile(HEADER_LINE_REGEX);
	private static HashMap<String,Integer> MONTH_DICT = new HashMap<String,Integer>();
	
	private static final String END_OF_MESSAGE = "----------------------------------------";
	private static final String VLAN_NETWORK_REGEX = "\\[([0-9]{1,5}):([0-9]{1,5})\\](.*)";
	private static int CAPTURE_GROUP_IFC = 1;
	private static int CAPTURE_GROUP_VLANID = 2;
	private static final Pattern VLAN_NETWORK_PATTERN = Pattern.compile(VLAN_NETWORK_REGEX);
	private static final String IPV4_PORT_REGEX = "([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3})\\.([0-9]{1,3}):([0-9]{1,5})";
	private static int CAPTURE_GROUP_IPV4_O1 = 1;
	private static int CAPTURE_GROUP_IPV4_O2 = 2;
	private static int CAPTURE_GROUP_IPV4_O3 = 3;
	private static int CAPTURE_GROUP_IPV4_O4 = 4;
	private static int CAPTURE_GROUP_PORT = 5;
	private static final Pattern IPV4_PORT_PATTERN = Pattern.compile(IPV4_PORT_REGEX);
	
	public static final String LOGFRAMETYPE_SIPMSG_SIP = "SIPMSG_SIP";
	public static final String LOGFRAMETYPE_SIPMSG_LOG = "SIPMSG_LOG";
	public static final String LOGFRAMETYPE_SIPD_LOG = "SIPD_LOG";
	public static final String LOGFRAMETYPE_MBCD_LOG = "MBCD_LOG";
	public static final String LOGFRAMETYPE_ALGD_LOG = "ALGD_LOG";

	public static final String TRANSPORT_UDP = "UDP";
	public static final String TRANSPORT_TCP = "TCP";
	public static final String TRANSPORT_SCTP = "SCTP";
	
	static {
        MONTH_DICT.put("Jan", new Integer(1));
        MONTH_DICT.put("Feb", new Integer(2));
		MONTH_DICT.put("Mar", new Integer(3));
		MONTH_DICT.put("Apr", new Integer(4));
		MONTH_DICT.put("May", new Integer(5));
		MONTH_DICT.put("Jun", new Integer(6));
		MONTH_DICT.put("Jul", new Integer(7));
		MONTH_DICT.put("Aug", new Integer(8));
		MONTH_DICT.put("Sep", new Integer(9));
		MONTH_DICT.put("Oct", new Integer(10));
		MONTH_DICT.put("Nov", new Integer(11));
		MONTH_DICT.put("Dec", new Integer(12));
	};

	/** year */
	private int year;

	/**
	 * Returns a AcmePacket object
	 *
	 * @return	The AcmePacket object
	 */
	public AcmePacket(String[] parserConfigParams) throws Exception {
		String yearString = parserConfigParams[0];
		this.year = Integer.parseInt(yearString);
		if((this.year < 0) || (this.year > 9999)) {
			throw new Exception("Invalid value for year parameter");
		};
	};
			
	/**	Parses one line to check whether it is a header line or not, so:
	 * - If it is the header line of a log frame, it parses it and returns the parsed data in a non-null T object
	 * - If not, then it returns null
	 *	@param	line
	 *	@return	the resulting LogFrame (or null if not a header line) */
	public LogFrame parseHeaderLine(String headerLine) {
		LogFrame logFrame = null;
		Matcher headerLineMatcher = HEADER_LINE_PATTERN.matcher(headerLine);
		if(headerLineMatcher.matches()) {
			TimeZone timeZone = TimeZone.getDefault();
			int year = this.year;
			try {
				int month = MONTH_DICT.get(headerLineMatcher.group(CAPTURE_GROUP_MONTH)).intValue();
				int day = Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_DAY));
				int hour = Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_HOUR));
				int minutes = Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_MINUTES));
				int seconds = Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_SECONDS));
				int microseconds = 1000 * Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_MILISECONDS));
				logFrame = new LogFrame(year, month, day, hour, minutes, seconds, microseconds);
				logFrame.setTimeZone(TimeZone.getDefault());
				logFrame.setGenericEvent(headerLineMatcher.group(CAPTURE_GROUP_GENERICDATA));
				try {
					/*
					"Jul  4 11:29:22.360 On [257:888]10.77.68.92:5060 sent to 10.38.2.136:5060";
					"Jul  4 11:29:22.392 On [257:888]10.77.68.92:5060 received from 10.38.2.136:5060";
					*/
					String[] genericDataFields = headerLineMatcher.group(CAPTURE_GROUP_GENERICDATA).split(" ");
					if(!genericDataFields[0].equals("On")){
						/* Not a SIP message
						 * As exceptions when parsing are assumed as failure to match a SIP message
						 * we just throw the exception so avoid a new if/else */
						throw new Exception("Not a SIP message");
					};
					Matcher vlanNetworkMatcher = VLAN_NETWORK_PATTERN.matcher(genericDataFields[1]);
					String action = genericDataFields[2];
					logFrame.setVlan(-1);
					String firstIpString = null;
					String secondIpString = null;
					String srcIpString = null;
					String dstIpString = null;
					int vlan = -1;
					if(vlanNetworkMatcher.matches()){
						vlan = Integer.parseInt(vlanNetworkMatcher.group(2));
						if(vlan != 0) {
							logFrame.setVlan(vlan);
						} else {
							logFrame.setVlan(-1);
						}
						firstIpString = vlanNetworkMatcher.group(3);
					} else {
						firstIpString = genericDataFields[1];
					};
					secondIpString = genericDataFields[4];
					if(action.equals("sent")){
						srcIpString = firstIpString;
						dstIpString = secondIpString;
					} else {
						srcIpString = secondIpString;
						dstIpString = firstIpString;
					};
					Matcher srcIpv4Matcher = IPV4_PORT_PATTERN.matcher(srcIpString);
					Matcher dstIpv4Matcher = IPV4_PORT_PATTERN.matcher(dstIpString);
					if(srcIpv4Matcher.matches()){
						logFrame.setSrcIp(InetAddress.getByName(srcIpv4Matcher.group(1)+"."+srcIpv4Matcher.group(2)+"."+srcIpv4Matcher.group(3)+"."+srcIpv4Matcher.group(4)));
						logFrame.setSrcPort(Integer.parseInt(srcIpv4Matcher.group(5)));
					};
					if(dstIpv4Matcher.matches()){
						logFrame.setDstIp(InetAddress.getByName(dstIpv4Matcher.group(1)+"."+dstIpv4Matcher.group(2)+"."+dstIpv4Matcher.group(3)+"."+dstIpv4Matcher.group(4)));
						logFrame.setDstPort(Integer.parseInt(dstIpv4Matcher.group(5)));
					};
				} catch (Exception e) {
					// Non-sipmsg message
					logFrame.setGenericEvent(headerLineMatcher.group(CAPTURE_GROUP_GENERICDATA));
				};
			} catch (Exception e) {
				logFrame = null;
				System.err.println("Exception when parsing the following line:");
				System.err.println(headerLine);
				System.err.println(e.toString());
			};
		};
		return logFrame;
	};

	/**	Postprocesses the input LogFrame, reading data from logLines and updating
	 *	other instance variables (at least sipLines)
	 *	@param	logFrame */
	public void postProcessLogFrame(LogFrame logFrame) {
		if(logFrame.getGenericEvent() != null) {
			/* We asume it is a SIP message, then we need to fill the sipLines
			 * To do so we read lines from logLines, but note that first of them
			 * is the header line we already parsed */
			if(logFrame.getLogLines().size() == 1) {
				logFrame.setGenericEvent(logFrame.getLogLines().get(0)); // In case exception is catched and frame is not discarded
				//throw new Exception("No SIP lines after header line: " + logFrame.getLogLines().get(0));
			} else {
				List<String> logLines = logFrame.getLogLines();
				ArrayList<String> sipLines = new ArrayList<String>();
				String line = null;
				for(int i=1; i<logLines.size(); i++) {
					line = logLines.get(i);
					if(line.equals(END_OF_MESSAGE)) break;
					sipLines.add(line);
				};
				logFrame.setSipLines(sipLines);
			};
		} else {
			/* It is a generic event. This time we complete it with subsequent lines
			 * To do so we read lines from logLines, but note that first of them
			 * is the header line we already parsed */
			StringBuilder stringBuilder = new StringBuilder();
			stringBuilder.append(parseHeaderLine(logFrame.getLogLines().get(0)).getGenericEvent());
			String line;
			for(int i=1; i<logFrame.getLogLines().size(); i++) {
				line = logFrame.getLogLines().get(i);
				stringBuilder.append("\r\n");
				stringBuilder.append(line);
			};
			logFrame.setGenericEvent(stringBuilder.toString());
		};
	};	

}