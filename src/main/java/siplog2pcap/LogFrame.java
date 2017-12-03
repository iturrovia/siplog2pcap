package siplog2pcap;

import java.util.List;
import java.util.ArrayList;
import java.net.InetAddress;
import java.util.TimeZone;

/**
 * LogFrame object represents a log entry (containing a timestamp and other log data)
 */
public class LogFrame {

	/* CLASS CONSTANTS */

	public static final int TRANSPORT_UDP = 17;
	public static final int TRANSPORT_TCP = 6;
	public static final int TRANSPORT_SCTP = 132;

	/* INSTANCE VARIABLES */

	/** year */
	private int year;

	/** month */
	private int month;

	/** day */
	private int day;

	/** hour */
	private int hour;

	/** minutes */
	private int minutes;

	/** seconds */
	private int seconds;

	/** microseconds */
	private int microseconds;

	/** timeZone */
	private TimeZone timeZone = null;

	/** vlan */
	private int vlan = -1;

	/** srcIp */
	private InetAddress srcIp = null;

	/** dstIp */
	private InetAddress dstIp = null;

	/** transport */
	private int transport = -1;

	/** srcPort */
	private int srcPort = -1;

	/** dstPort */
	private int dstPort = -1;

	/** logLines */
	private List<String> logLines = new ArrayList();

	/** sipLines */
	private List<String> sipLines = null;

	/** genericEvent */
	private String genericEvent = null;

	/**
	 *	CONSTRUCTOR
	 *	Returns a LogFrame object
	 *	@param	year		the year
	 *	@param	month		the month
	 *	@param	day			the day
	 *	@param	hour		the hour
	 *	@param	minutes		the minutes
	 *	@param	seconds		the seconds
	 *	@param	microseconds	the microseconds
	 *	@return	The LogFrame object
	 */
	public LogFrame(int year, int month, int day, int hour, int minutes, int seconds, int microseconds) {

		/* Setting mandatory variables
		 * Many different parsers will need to create this object
		 * some fields are optional and the application will eventually implement default behaviors for them
		 * but for the date-ish fields, supporting all different combinations of some of them missing leads to
		 * counter-intuitive behaviors, so we prefer to make the different parsers to explicitly define them and
		 * implement their default values if they want to
		 */
		this.year = year;
		this.month = month;
		this.day = day;
		this.hour = hour;
		this.minutes = minutes;
		this.seconds = seconds;
		this.microseconds = microseconds;

		/* Remaining ones take nullish values at object creation time
		 * they can be set during the parsing process (methods implemented by LogFrameParser interface)
		 * otherwise they will be assigned default values when transforming to PCAP (see AppCore class) */
		this.timeZone = null;
		this.vlan = -1;
		this.srcIp = null;
		this.dstIp = null;
		this.transport = -1;
		this.srcPort = -1;
		this.dstPort = -1;
		this.logLines = new ArrayList<String>();
		this.sipLines = null;
		this.genericEvent = null;
	};

	/* SETTERS */

	/** Sets the year
	 *	@param	year */
	public void setYear(int year) { this.year = year; };

	/**	Returns the year
	 *	@return	the year */
	public int getYear() { return this.year; };

	/**	Sets the month
	 *	@param	month */
	public void setMonth(int month) { this.month = month; };

	/**	Sets the day
	 *	@param	day */
	public void setDay(int day) { this.day = day; };

	/**	Sets the hour
	 * @param	hour */
	public void setHour(int hour) { this.hour = hour; };

	/**	Sets the minutes
	 *	@param	minutes */
	public void setMinutes(int minutes) { this.minutes = minutes; };

	/**	Sets the seconds
	 *	@param	seconds */
	public void setSeconds(int seconds) { this.seconds = seconds; };

	/**	Sets the microseconds
	 *	@param	microseconds */
	public void setMicroseconds(int microseconds) { this.microseconds = microseconds; };

	/**	Sets the timeZone
	 *	@param	timeZone */
	public void setTimeZone(TimeZone timeZone) { this.timeZone = timeZone; };

	/**	Sets the transport
	 *	@param	transport */
	public void setTransport(int transport) { this.transport = transport; };

	/**	Sets the srcPort
	 *	@param	srcPort */
	public void setSrcPort(int srcPort) { this.srcPort = srcPort; };

	/**	Sets the dstPort
	 *	@param	dstPort */
	public void setDstPort(int dstPort) { this.dstPort = dstPort; };

	/**	Sets the vlan
	 *	@param	vlan */
	public void setVlan(int vlan) { this.vlan = vlan; };

	/**	Sets the srcIp
	 *	@param	srcIp */
	public void setSrcIp(InetAddress srcIp) { this.srcIp = srcIp; };

	/**	Sets the dstIp
	 *	@param	dstIp */
	public void setDstIp(InetAddress dstIp) { this.dstIp = dstIp; };

	/**	Sets the sipLines
	 *	@param	sipLines */
	public void setSipLines(List<String> sipLines) { this.sipLines = sipLines; };

	/**	Sets the genericEvent
	 *	@param	genericEvent */
	public void setGenericEvent(String genericEvent) { this.genericEvent = genericEvent; };

	/* GETTERS */

	/**	Returns the month
	 *	@return	the month */
	public int getMonth() { return this.month; };

	/**	Returns the day
	 *	@return	the day */
	public int getDay() { return this.day; };

	/**	Returns the hour
	 *	@return	the hour */
	public int getHour() { return this.hour; };

	/**	Returns the minutes
	 *	@return	the minutes */
	public int getMinutes() { return this.minutes; };

	/**	Returns the seconds
	 *	@return	the seconds */
	public int getSeconds() { return this.seconds; };

	/**	Returns the microseconds
	 *	@return	the microseconds */
	public int getMicroseconds() { return this.microseconds; };

	/**	Returns the timeZone
	 *	@return	the timeZone */
	public TimeZone getTimeZone() { return this.timeZone; };

	/**	Returns the transport
	 *	@return	the transport */
	public int getTransport() { return this.transport; };

	/**	Returns the srcPort
	 *	@return	the srcPort */
	public int getSrcPort() { return this.srcPort; };

	/**	Returns the dstPort
	 *	@return	the dstPort */
	public int getDstPort() { return this.dstPort; };

	/**	Returns the vlan
	 *	@return	the vlan */
	public int getVlan() { return this.vlan; };

	/**	Returns the srcIp
	 *	@return	the srcIp */
	public InetAddress getSrcIp() { return this.srcIp; };

	/**	Returns the dstIp
	 *	@return	the dstIp */
	public InetAddress getDstIp() { return this.dstIp; };

	/**	Returns the logLines
	 *	@return	the logLines */
	public List<String> getLogLines() { return this.logLines; };

	/**	Returns the sipLines
	 *	@return	the sipLines */
	public List<String> getSipLines() { return this.sipLines; };

	/**	Returns the genericEvent
	 *	@return	the genericEvent */
	public String getGenericEvent() { return this.genericEvent; };

	/**	Builds the SIP message by using the sipLines
	 *	@return	the SIP message */
	public String getSipMessage() {
		if(this.getSipLines() == null) return null;
		StringBuilder sb = new StringBuilder();
		for(String line : this.getSipLines()) {
			sb.append(line);
			sb.append("\r\n");
		};
		return sb.toString();
	};

	/**
	 * This method infers whether the content a SIP message was sent over UDP, TCP or SCTP
	 * by checking the message content (Via header in particular)
	 * @return	The inferred transport protocol
	 */
	public int inferSipTransport() {
		int transport = TRANSPORT_UDP; // Default
		String sipHeader;
		for(String sipLine : this.getSipLines()) {
			sipHeader = sipLine.toUpperCase();
			if(sipHeader.indexOf("VIA") == 0) {
				if(sipHeader.indexOf("SIP/2.0/UDP") != -1) {
					transport = TRANSPORT_UDP;
				} else if((sipHeader.indexOf("SIP/2.0/TCP") != -1) || (sipHeader.indexOf("SIP/2.0/TLS") != -1)) {
					transport = TRANSPORT_TCP;
				} else if((sipHeader.indexOf("SIP/2.0/SCTP") != -1) || (sipHeader.indexOf("SIP/2.0/TLS-SCTP") != -1)) {
					transport = TRANSPORT_SCTP;
				} else {
					/* Incomplete SIP message. This happens when the message has been fragmented, so...
					 * 		- We will assume it was fragmented at TCP (but we are just guessing)
					 *		- If it was fragmented at SCTP or even at IP, Wireshark will not be able to reconstruct the whole SIP message */
					transport = TRANSPORT_TCP;
				}
				break;
			};
		}
		return transport;
	}

	/**	Returns a string representation of the object content
	 *	@return	the string representation of the object content */
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("{ ");
		sb.append("\"year\": ");
		sb.append(String.valueOf(this.year));
		sb.append(", \"month\": ");
		sb.append(String.valueOf(this.month));
		sb.append(", \"day\": ");
		sb.append(String.valueOf(this.day));
		sb.append(", \"hour\": ");
		sb.append(String.valueOf(this.hour));
		sb.append(", \"minutes\": ");
		sb.append(String.valueOf(this.minutes));
		sb.append(", \"seconds\": ");
		sb.append(String.valueOf(this.seconds));
		sb.append(", \"microseconds\": ");
		sb.append(String.valueOf(this.microseconds));
		sb.append(", \"timeZone\": ");
		if(this.timeZone != null) { 
			sb.append(this.timeZone.toString());
		} else sb.append("null");
		sb.append(", \"vlan\": ");
		sb.append(String.valueOf(this.vlan));
		sb.append(", \"srcIp\": ");
		if(this.srcIp != null) {
			sb.append(this.srcIp.toString());
		} else sb.append("null");
		sb.append(", \"dstIp\": ");
		if(this.dstIp != null) {
			sb.append(this.dstIp.toString());
		} else sb.append("null");
		sb.append(", \"transport\": ");
		sb.append(String.valueOf(this.transport));
		sb.append(", \"srcPort\": ");
		sb.append(String.valueOf(this.srcPort));
		sb.append(", \"dstPort\": ");
		sb.append(String.valueOf(this.dstPort));
		sb.append(", \"logLines\": [");
		for(String line: this.logLines) {
			sb.append("\r\n");
			sb.append(line);
		}
		sb.append("]\r\n");
		sb.append(", \"sipLines\": ");
		if(this.sipLines != null) {
			sb.append("[");
			for(String line: this.sipLines) {
				sb.append("\r\n");
				sb.append(line);
			}
			sb.append("]\r\n");
		} else sb.append("null");
		sb.append(", \"genericEvent\": ");
		if(this.genericEvent != null) {
			sb.append(this.genericEvent);
		} else sb.append("null");
		sb.append(" }");
		return sb.toString();
	};
	
}