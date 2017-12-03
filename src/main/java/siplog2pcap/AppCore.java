package siplog2pcap;
import jfnlite.Fn;
import java.io.File;
import java.io.FileOutputStream;
import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.HashMap;
import java.net.InetAddress;
import java.util.Date;
import java.util.TimeZone;
import java.text.SimpleDateFormat;

/**
 * Class implementing the set of functionality requred for siplog2pcap
 *
 * This class contains the general functionality required for siplog2pcap
 * and is defined as an abstract one just to be extended by specific user interfaces
 * we might want to create (either command line or graphical user interfaces).
 */
public abstract class AppCore {

	/* CONSTANTS */
	
	public static final String TYPE_PJSUA = "pjsua";
	public static final String TYPE_PHONER_LITE = "phoner-lite";

	private static final byte[] DEFAULT_MAC = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
	private static InetAddress DEFAULT_IP = null; // Will be set to 0.0.0.0 in static class initiation block

	/** Build version. */
	public static final String BUILD = "0.1.0.build20171203";

	static {
		try{
			DEFAULT_IP = InetAddress.getByName("0.0.0.0");
		} catch (java.net.UnknownHostException e) {
			// Do nothing, as will never happen
		}
	}

	/**
	 * Creates a date using its year, month, day, hour, minute and second components
	 * 
	 * @param	year	the year component
	 * @param	month	the month component
	 * @param	day		the day component
	 * @param	hour	the hour component
	 * @param	minute	the minute component
	 * @param	second	the second component
	 * @return			the date
	 */
	public static Date createDate(int year, int month, int day, int hours, int minutes, int seconds, TimeZone timeZone) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		sdf.setTimeZone(timeZone);
		String dateInString = Integer.toString(year)+"-"+Integer.toString(month)+"-"+Integer.toString(day)+" "+Integer.toString(hours)+":"+Integer.toString(minutes)+":"+Integer.toString(seconds);
		Date date = null;
		try {
			date = sdf.parse(dateInString);
		} catch (Exception e) {
			// This exception should never take place, but it is mandatory to try-catch
			System.err.println("Exception in createDate:");
			System.err.println(e.toString());
			throw(new RuntimeException(e));
		};
		return date;
	};

	public static byte[] createGenericPcapFrame(Date date, int microseconds, int vlan, InetAddress srcIp, InetAddress dstIp, int transport, int srcPort, int dstPort, byte[] payload) {
		byte[] transportPacket = null;
		byte[] ipPacket = null;
		if(transport == Pcap.IP_PROTOCOL_UDP) {
			transportPacket = Pcap.createUdpPacket(srcPort, dstPort, payload);
			ipPacket = Pcap.createIpv4Packet(srcIp, dstIp, Pcap.IP_PROTOCOL_UDP, transportPacket);
		} else if(transport == Pcap.IP_PROTOCOL_TCP) {
			transportPacket = Pcap.createTcpPacket(srcPort, dstPort, payload, srcIp, dstIp);
			ipPacket = Pcap.createIpv4Packet(srcIp, dstIp, Pcap.IP_PROTOCOL_TCP, transportPacket);
		} else if(transport == Pcap.IP_PROTOCOL_SCTP) {
			transportPacket = Pcap.createSctpPacket(srcPort, dstPort, payload, srcIp, dstIp);
			ipPacket = Pcap.createIpv4Packet(srcIp, dstIp, Pcap.IP_PROTOCOL_SCTP, transportPacket);
		} else {
			// UDP by default
			transportPacket = Pcap.createUdpPacket(srcPort, dstPort, payload);
			ipPacket = Pcap.createIpv4Packet(srcIp, dstIp, Pcap.IP_PROTOCOL_TCP, transportPacket);
		}
		byte[] ethernetPacket = Pcap.createEthernetPacket(DEFAULT_MAC, DEFAULT_MAC, Pcap.ETHERTYPE_IPV4, ipPacket, vlan);
		int dateInt = (int) (date.getTime()/1000);
		byte[] pcapFrame = Pcap.createPcapFrame(dateInt, microseconds, ethernetPacket.length, ethernetPacket);
		return pcapFrame;
	}

	/**
	 * Converts a LogFrame into a PCAP frame
	 * @param	logFrame	input LogFrame
	 * @return				the PCAP frame 
	 */
	public static Fn.Function<LogFrame,byte[]> logFrameToPcapFrame = new Fn.Function<LogFrame,byte[]>() {
		public byte[] apply(LogFrame logFrame) {
			byte[] transportPacket = null;
			byte[] tcpPacket = null;
			byte[] sctpPacket = null;
			byte[] ipPacket = null;
			byte[] pcapFrame = null;
			byte[] payload = null;

			/* Mandatory fields, which we assume are always defined in the logFrame */
			int year = logFrame.getYear();
			int month = logFrame.getMonth();
			int day = logFrame.getDay();
			int hour = logFrame.getHour();
			int minutes = logFrame.getMinutes();
			int seconds = logFrame.getSeconds();
			int microseconds = logFrame.getMicroseconds();

			/* Optional fields */
			TimeZone timeZone = logFrame.getTimeZone();
			if(timeZone == null) timeZone = TimeZone.getDefault();
			int vlan = logFrame.getVlan();
			InetAddress srcIp = logFrame.getSrcIp();
			InetAddress dstIp = logFrame.getDstIp();
			int transport = logFrame.getTransport();
			int srcPort = logFrame.getSrcPort();
			int dstPort = logFrame.getDstPort();

			/* Now preparing the pcapFrame */
			Date date = createDate(year, month, day, hour, minutes, seconds, timeZone);
			if(logFrame.getSipLines() != null) {
				/* This is a SIP message */
				if(srcIp == null) srcIp = DEFAULT_IP;
				if(dstIp == null) dstIp = DEFAULT_IP;
				if(transport == -1) transport = logFrame.inferSipTransport();
				if(srcPort == -1) srcPort = 5060;
				if(dstPort == -1) dstPort = 5060;
				String message = logFrame.getSipMessage();
				payload = message.getBytes();
			} else {
				/* This is a generic event, to be inserted as syslog */
				vlan = -1;
				srcIp = DEFAULT_IP;
				dstIp = DEFAULT_IP;
				transport = Pcap.IP_PROTOCOL_UDP;
				srcPort = Pcap.UDP_PROTOCOL_SYSLOG;
				dstPort = Pcap.UDP_PROTOCOL_SYSLOG;
				String message = logFrame.getGenericEvent();
				payload = message.getBytes();
			};
			pcapFrame = createGenericPcapFrame(date, microseconds, vlan, srcIp, dstIp, transport, srcPort, dstPort, payload);
			//System.out.println(logFrame.toString());
			return pcapFrame;
		}
	};
	
	/**
	 * Handles Text Output Event
	 *
	 * @param	textOutput	the text to output
	 */
	public abstract void onTextOutput(String textOutput);
	
	/**
	 * Handles User Interface Output
	 *
	 * @param	textOutput	the text to output
	 */
	public abstract void onFinish(int retValue);

	/**
	 * Writes a stream of byte arrays into the given file.
	 *
	 * @param	bytesIterable	iterable of byte arrays
	 * @param	outputFilePath	path to the output file
	 * @return					the result of the operation
	 */
	private boolean writeToFile(Iterator<byte[]> bytesIterator, String outputFilePath){
		boolean success = false;
		try {
			OutputStream outputStream = null;
			try {
				outputStream = new BufferedOutputStream(new FileOutputStream(outputFilePath));
				while(bytesIterator.hasNext()){
					outputStream.write(bytesIterator.next());
				}
				success = true;
			} finally {
				if(outputStream != null) {
					outputStream.close();
				}
			}
		} catch(FileNotFoundException e){
			onTextOutput("ERROR:  Failed to open output file " + outputFilePath);
		} catch(IOException e){
			onTextOutput("ERROR:  Exception when working with output file " + outputFilePath);
		}
		return success;
	}

	/**
	 * Writes a stream of byte arrays into the given file.
	 *
	 * @param	bytesIterable	iterable of byte arrays
	 * @param	outputFilePath	path to the output file
	 * @return					the result of the operation
	 */
	private boolean writeToFile(Iterable<byte[]> bytesIterable, String outputFilePath){
		return writeToFile(bytesIterable.iterator(), outputFilePath);
	}
	
	/**
	 * Processess a set of log Files, creating a PCAP file and generating events to be handled
	 * by onTextOutput() and onFinished() methods
	 *
	 * @param	logType 	the input log type
	 * @param	logFile		the input log file to read
	 * @param	pcapFile 	the output PCAP file to generate
	 */
	public void processLogFile(LogFrameParser parser, File logFile, File pcapFile) {
		String result = null;
		String summary = null;
		Iterator<String> logLines = null;
		this.onTextOutput("siplog2pcap.v" + BUILD + "\r\n");
		try {
			logLines = new LineIterator(logFile);
		} catch(RuntimeException e) {
			e.printStackTrace();
			this.onTextOutput(e.toString());
			this.onFinish(1);
		}
		LogLinesParser logLinesParser = new LogLinesParser(parser);
		Iterator<LogFrame> logFrames = logLinesParser.parse(logLines);
		Iterator<byte[]> pcapFrames = Fn.map(logFrames, logFrameToPcapFrame);
		byte[] pcapFileHeader = Pcap.createPcapFileHeader(Pcap.LINKTYPE_ETHERNET);
		this.onTextOutput("Writing to " + pcapFile.getPath() + " ...\r\n");
		if(writeToFile(Fn.concat(Fn.iteratorOf(pcapFileHeader), pcapFrames), pcapFile.getPath())) {
			this.onTextOutput("FINISHED!");
		} else {
			this.onTextOutput("FAILED");
		};
		this.onFinish(1);
	}
	
}