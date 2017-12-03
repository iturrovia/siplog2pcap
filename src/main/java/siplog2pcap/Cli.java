package siplog2pcap;
import java.util.List;
import java.util.ArrayList;
import java.io.File;
import jfnlite.Fn;

/**
 * Command Line Interface for siplog2pcap
*/
public class Cli extends AppCore {

	/*
	 * return value element
	 */
	public int retValue;
	
	/**
	 * Constructs the Cli object and initializes its return value
	 */
	public Cli() {
		this.retValue = 0;
	}
	
	/**
	 * Writes text console output
	 *
	 * @param	textOutput	the text to output
	 */
	private void consoleOutput(String textOutput){
		System.out.println(textOutput);
	}
	
	/**
	 * Handles Text Output Event
	 *
	 * @param	textOutput	the text to output
	 */
	public void onTextOutput(String textOutput) {
		consoleOutput(textOutput);
	}
	
	/**
	 * Handles User Interface Output
	 *
	 * @param	textOutput	the text to output
	 */
	public void onFinish(int retValue) {
		this.retValue = retValue;
	}
	
	/**
	 * Main method
	 *
	 * @param	args	arguments
	 */
	public static void main(String[] args) {
		String HELP_STRING =
		"siplog2pcap.v" + Cli.BUILD + ":\r\n" +
		"\r\n" +
		"Usage for PJSUA log file. Note that date and local IP are provided as additional parameters (as not included in the logs):\r\n" +
		"\tsiplog2pcap --pjsua <input_log_file> <output_pcap_file> <date(yyyy-mm-dd)> <local_ip>" + "\r\n" +
		"\r\n" +
		"Usage for Oracle SBC (fomerly AcmePacket) sipmsg log file. Note that year is provided as an additional parameter (as not included in the logs):\r\n" +
		"\tsiplog2pcap --acme-packet <input_log_file> <output_pcap_file> <year>" + "\r\n";
		;
		byte[] pcapFile = null;
		byte[] fileContents = null;
		String option = null;
		Cli cli = new Cli();
		LogFrameParser parser = null;
		
		/*
		 * Processing command line args
		 * I wonder why java standard library does not include an implementation for this...
		 */
		if(args.length > 0) {
			option = args[0];
			if(option == "-h") {
				cli.consoleOutput(HELP_STRING);
				cli.retValue = 1;
			} else if(args.length >= 3) {
				String[] parserConfigParams = new String[args.length - 3];
				for(int i=0; i < parserConfigParams.length; i++) {
					parserConfigParams[i] = args[3 + i];
				}
				try {
					if(option.equals("--acme-packet")) {
						parser = new siplog2pcap.parsers.AcmePacket(parserConfigParams);
					} else if(option.equals("--pjsua")) {
						parser = new siplog2pcap.parsers.Pjsua(parserConfigParams);
					};
				} catch(Exception e) {
					parser = null;
				}
				if(parser != null) {
					String inputFilePath = args[1];
					String outputFilePath = args[2];
					File inputFile = new File(inputFilePath);
					File outputFile = new File(outputFilePath);
					cli.processLogFile(parser, inputFile, outputFile);
				} else {
					cli.consoleOutput(HELP_STRING);
					cli.retValue = 1;
				}
			} else {
				cli.consoleOutput(HELP_STRING);
				cli.retValue = 1;
			};
		} else {
			cli.consoleOutput(HELP_STRING);
			cli.retValue = 1;
		};
		System.exit(cli.retValue);
	}
	
}
