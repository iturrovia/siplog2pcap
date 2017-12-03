package siplog2pcap.parsers;

import siplog2pcap.LogFrame;
import siplog2pcap.LogFrameParser;
import java.util.ArrayList;
import java.lang.StringBuilder;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Date;
import java.util.TimeZone;
import java.text.SimpleDateFormat;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Iterator;
import java.net.InetAddress;
import jfnlite.Fn;

/**
 * ApktLog class is a collection of tools to parse APKT logs
 */
public class Pjsua implements LogFrameParser {
	
	private static final String HEADER_LINE_REGEX = "^\\s*([\\d]{1,2}):([\\d]{1,2}):([\\d]{1,2}).([\\d]{3})[\\s\\t]+([\\w\\.]+)[\\s\\t]+(.*)$";
	private static final Pattern HEADER_LINE_PATTERN = Pattern.compile(HEADER_LINE_REGEX);
	private static final int CAPTURE_GROUP_HOUR = 1;
	private static final int CAPTURE_GROUP_MINUTES = 2;
	private static final int CAPTURE_GROUP_SECONDS = 3;
	private static final int CAPTURE_GROUP_MILISECONDS = 4;
	private static final int CAPTURE_GROUP_MODULE = 5;
	private static final int CAPTURE_GROUP_EVENTDATA = 6;

	private static final String SIP_EVENT_REGEX = "^\\.*(TX|RX)[\\s\\t]+(\\d+)[\\s\\t]+bytes[\\s\\t]+(Request|Response)[\\s\\t]+msg[\\s\\t]+[^\\(]+\\([^)]+\\)[\\s\\t]+(to|from)[\\s\\t]+(UDP|udp|TCP|tcp|TLS|tls|SCTP|sctp)[\\s\\t]+([\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}):(\\d+).*$";
	private static final Pattern SIP_EVENT_PATTERN = Pattern.compile(SIP_EVENT_REGEX);
	private static final int CAPTURE_GROUP_TXRX = 1;
	private static final int CAPTURE_GROUP_BYTES = 2;
	private static final int CAPTURE_GROUP_REQUESTRESPONSE = 3;
	private static final int CAPTURE_GROUP_TOFROM = 4;
	private static final int CAPTURE_GROUP_TRANSPORT = 5;
	private static final int CAPTURE_GROUP_IP = 6;
	private static final int CAPTURE_GROUP_PORT = 7;

	private static final String END_OF_MESSAGE = "--end msg--";

	public static final String TRANSPORT_UDP = "UDP";
	public static final String TRANSPORT_TCP = "TCP";
	public static final String TRANSPORT_TLS = "TLS";
	public static final String TRANSPORT_SCTP = "SCTP";
	
	static {
	};

	/** year */
	private int year;

	/** month */
	private int month;

	/** day */
	private int day;

	/** timeZone */
	private TimeZone timeZone;

	/** localIp */
	private InetAddress localIp;

	/**
	 * Returns a Pjsua object
	 *
	 * @return	The Pjsua object
	 */
	public Pjsua(String[] parserConfigParams) throws Exception {
		String dateString = parserConfigParams[0];
		String ipString = parserConfigParams[1];
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
		this.timeZone = TimeZone.getDefault();
		sdf.setTimeZone(this.timeZone);
		Date date = null;
		try {
			date = sdf.parse(dateString);
			this.localIp = InetAddress.getByName(ipString);
		} catch (Exception e) {
			// The exception is caused by bad format introduced by application, so we just forward it
			throw(e);
		};
		GregorianCalendar calendar = new GregorianCalendar(this.timeZone);
		calendar.setTime(date);
		this.year = calendar.get(GregorianCalendar.YEAR);
		this.month = 1 + calendar.get(GregorianCalendar.MONTH);
		this.day = calendar.get(GregorianCalendar.DAY_OF_MONTH);
	};
			
	/**	Parses one line to check whether it is a header line or not, so:
	 * - If it is the header line of a log frame, it parses it and returns the parsed data in a non-null object
	 * - If not, then it returns null
	 *	@param	headerLine
	 *	@return	the resulting LogFrame (or null if not a header line) */
	public LogFrame parseHeaderLine(String headerLine) {
		LogFrame logFrame = null;
		Matcher headerLineMatcher = HEADER_LINE_PATTERN.matcher(headerLine);
		if(headerLineMatcher.matches()) {
			/* Logs contain no date info, but we get it from the parser parameters */
			TimeZone timeZone = this.timeZone;
			int year = this.year;
			int month = this.month;
			int day = this.day;
			try {
				int hour = Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_HOUR));
				int minutes = Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_MINUTES));
				int seconds = Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_SECONDS));
				int microseconds = 1000 * Integer.parseInt(headerLineMatcher.group(CAPTURE_GROUP_MILISECONDS));
				String genericEvent = headerLineMatcher.group(CAPTURE_GROUP_EVENTDATA);
				logFrame = new LogFrame(year, month, day, hour, minutes, seconds, microseconds);
				logFrame.setTimeZone(timeZone);
				logFrame.setGenericEvent(genericEvent);
				Matcher sipEventMatcher = SIP_EVENT_PATTERN.matcher(genericEvent);
				if(sipEventMatcher.matches()) {
					// It is a SIP message
					String txOrRx = sipEventMatcher.group(CAPTURE_GROUP_TXRX);
					String transportStr = sipEventMatcher.group(CAPTURE_GROUP_TRANSPORT).toUpperCase();
					int transport = LogFrame.TRANSPORT_UDP; // Default
					if(transportStr.equals(TRANSPORT_TCP) || transportStr.equals(TRANSPORT_TLS)) {
						transport = LogFrame.TRANSPORT_TCP;
					} else if(transportStr.equals(TRANSPORT_SCTP)) {
						transport = LogFrame.TRANSPORT_SCTP;
					};
					InetAddress ip = InetAddress.getByName(sipEventMatcher.group(CAPTURE_GROUP_IP));
					int port = Integer.parseInt(sipEventMatcher.group(CAPTURE_GROUP_PORT));
					logFrame.setVlan(-1);
					logFrame.setTransport(transport);
					if(txOrRx.equals("TX")) {
						logFrame.setSrcIp(this.localIp);
						logFrame.setDstIp(ip);
						logFrame.setDstPort(port);
					} else {
						logFrame.setSrcIp(ip);
						logFrame.setSrcPort(port);
						logFrame.setDstIp(this.localIp);
					};
					logFrame.setSipLines(new ArrayList<String>());
				}
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
		if(logFrame.getSipLines() != null) {
			/* We asume it is a SIP message, then we need to fill the sipLines
			 * To do so we read lines from logLines, but note that first of them
			 * is the header line we already parsed */
			if(logFrame.getLogLines().size() == 1) {
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