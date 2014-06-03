package crawler;

import java.io.File;
import java.util.ArrayList;
import java.util.Scanner;

import crawler.Website;

/**
 * Object containing a list of websites.
 *
 */
public class WebsitesList {
	private ArrayList<Website> websites;
	private String status;

	/**
	 * Constructor.
	 *
	 * @param file: the name of the websites file.
	 * @param start: the start index of the range.
	 * @param end: the end index of the range.
	 */
	public WebsitesList(String file, int start, int end) {
		websites = new ArrayList<Website>();
		read(file, start, end);
	}

	/**
	 * Gets the list of websites.
	 *
	 * @return an ArrayList of Website objects.
	 */
	public ArrayList<Website> getWebsites() {
		return websites;
	}

	/**
	 * Returns the status of the file's parsing
	 *
	 * @return a String containing the status
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * Reads and parses the websites file.
	 *
	 * @param file: the name of the websites file.
	 * @param start: the start index of the range.
	 * @param end: the end index of the range.
	 */
	private void read(String file, int start, int end) {
		if(start <= 0) {
			status = "The range starts at 1";
		}
		// Only needed for Alexa topsites file
		/*else if(start > 1000000 || end > 1000000) {
			System.out.println("The range ends at 1000000");
		}*/
		else if(start > end) {
			status = "The range is incorrect";
		}
		else {
			try {
				Scanner scanner = new Scanner(new File(file));
				while(scanner.hasNextLine()) {
					String line = scanner.nextLine();
					String[] tokens = line.split(",");
					int position = Integer.parseInt(tokens[0]);
					String url = tokens[1];

					// Position is in the good range: add the website
					if(position >= start && position <= end) {
						Website website = new Website(position, url);
						websites.add(website);
					}
					// Position is after the range: break the loop
					else if(position > end) {
						break;
					}
				}
				scanner.close();
				if(websites.size() != 0) {
					if(websites.size() == 1) {
						status = "1 website loaded";
					}
					else {
						status = websites.size() + " websites loaded";
					}
				}
				else {
					status = "The range does not correspond to any website in the file";
				}
			} catch (Exception e) {
				status = "An error occurred while accessing the websites file.\n"
						+ "> You can download a list at http://www.alexa.com/topsites";
			}
		}
	}
}
