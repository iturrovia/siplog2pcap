package siplog2pcap;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.lang.UnsupportedOperationException;
import java.util.List;
import java.util.ArrayList;

public class LogLinesParser {

	private LogFrameParser logFrameParser;

	/**
	 * Returns a LogLinesParser object
	 *
	 * @return	The LogLinesParser object
	 */
	public LogLinesParser(LogFrameParser logFrameParser) {
		this.logFrameParser = logFrameParser;
	};

	/**
	 * This method gets an iterator of lines and returns an iterator of LogFrames:
	 *
	 * @param	lineIterator	the log line iterator
	 * @return					an iterator of LogFrames
	 */
	public Iterator<LogFrame> parse(Iterator<String> lineIterator) {
		return new LogFrameIterator(lineIterator);
	}

	/**
	 * LogFrameIterator object represents an iteration of log frames, which are
	 * eventually read from one or more log files.
	 */
	private class LogFrameIterator implements Iterator<LogFrame> {
		
		/*
		 * Instance variables
		 */
		private Iterator<String> lineIterator;
		private LogFrame cachedNext;
		private String cachedLogLine;
		
		/**
		 * Constructor method taking a byte array as input parameter
		 * The file type is inferred from the byte content
		 * 
		 * @param	lineIterator	an iterator with the log lines
		 * @return				the newly created LogFrameIterator object
		 */
		public LogFrameIterator(Iterator<String> lineIterator) {
			this.lineIterator = lineIterator;
			this.cachedNext = null;
			this.cachedLogLine = null;
		}
		
		private LogFrame getNext() {
			LogFrame next = null;
			LogFrame tmpLogFrame = null;
			String logLine = null;
			
			if(this.cachedNext != null) {
				// We've already read next object from previous invocaton of hasNext() method
				next = this.cachedNext;
				this.cachedNext = null;
			} else {
				/*
				 * We look for the opening header line
				 */
				 // First of all we read the cached log line (if any)
				logLine = this.cachedLogLine;
				if(logLine != null) {
					this.cachedLogLine = null;
					tmpLogFrame = LogLinesParser.this.logFrameParser.parseHeaderLine(logLine);
				};
				// We consume log lines until we find a header line
				while((tmpLogFrame == null) && (this.lineIterator.hasNext())) {
					logLine = this.lineIterator.next();
					tmpLogFrame = LogLinesParser.this.logFrameParser.parseHeaderLine(logLine);
				};
				/*
				 * Now we should have found the header line if any
				 */
				if(tmpLogFrame != null) {
					// Found header line, so we create the LogFrame and add the header line
					next = tmpLogFrame;
					next.getLogLines().add(logLine);
					// Now we add extra lines if any
					while(this.lineIterator.hasNext()) {
						logLine = this.lineIterator.next();
						tmpLogFrame = LogLinesParser.this.logFrameParser.parseHeaderLine(logLine);
						if(tmpLogFrame == null) {
							next.getLogLines().add(logLine);
						} else {
							this.cachedLogLine = logLine;
							break;
						};
					};
					if(!this.lineIterator.hasNext()) {
						this.cachedLogLine = null;
					};
				};
			};
			if(next != null) LogLinesParser.this.logFrameParser.postProcessLogFrame(next);
			return next;
		};
		
		/**
		 * Returns true if the iteration has more elements.
		 * (In other words, returns true if next would return an element rather than throwing an exception.)
		 * 
		 * @return	whether the iteration has more elements
		 */
		public boolean hasNext() {
			this.cachedNext = this.getNext();
			return (this.cachedNext != null);
		}
		
		/**
		 * Returns the next element in the iteration.
		 * 
		 * @return	the next element in the iteration.
		 */
		public LogFrame next() {
			LogFrame next = this.getNext();
			if(next == null) {
				throw(new NoSuchElementException());
			};
			return next;
		}
		
		/**
		 * Removes from the underlying collection the last element returned by the iterator (optional operation). This method can be called only once per call to next. 
		 * The behavior of an iterator is unspecified if the underlying collection is modified while the iteration is in progress in any way other than by calling this method.
		 * 
		 */
		public void remove() {
			throw(new UnsupportedOperationException());
		}
		
	}
}
