package crawler;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileFilter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Map.Entry;
import java.util.concurrent.TimeUnit;

import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.UnhandledAlertException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.firefox.internal.ProfilesIni;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.remote.UnreachableBrowserException;

import crawler.WebsitesList;
import crawler.Website;
import crawler.CounterAndDeleterFileVisitor;

public class Crawler {

	private static boolean debug;
	private static WebDriver driver;
	private static FileWriter logsFile;
	private static SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy - HH:mm:ss");
	private static ArrayList<String> websitesFailed = new ArrayList<String>();
	private static ArrayList<String> websitesTimeout = new ArrayList<String>();
	private static int websitesVisited = 0;
	private static Scanner scanner;
	private static String flashCookiesPath;
	private static Map<String, Integer> flashCookiesPerWebsite;
	private static String firefoxCookiesDB;

	/**
	 * Starts the crawler
	 *
	 * @param directoryName
	 * @param ffprofile
	 * @param websitesFile
	 * @param startIndex
	 * @param endIndex
	 * @param attempts
	 * @param showDebug
	 * @param restart
	 * @param timeout
	 */
	public static void launchCrawler(final String directoryName, String ffprofile, String websitesFile,
			int startIndex, int endIndex, int attempts, boolean showDebug, int restart, int timeout) {
		debug = showDebug;
		String start = dateFormat.format(new Date()) + " - Launching crawler...\n"
				+ "   directory: " + directoryName + "\n"
				+ "   websites file: " + websitesFile + "\n"
				+ "   start index: " + startIndex + ", end index: " + endIndex + "\n"
				+ "   Firefox profile: " + ffprofile + "\n"
				+ "   restart value: " + restart + "\n"
				+ "   number of attempts per website: " + attempts + "\n"
				+ "   timeout: " + timeout + " seconds\n"
				+ "   debug: " + debug;
		System.out.println(start);

		// Start the console input scanner
		scanner = new Scanner(System.in);

		// Check the file system permissions
		try {
			if(!checkDirectories(directoryName)) {
				System.out.println(dateFormat.format(new Date()) + " - Error: cannot create the required directory.\n"
						+ "> Please check your file system permissions.");
				System.exit(1);
			}
			logsFile = new FileWriter(new File(directoryName+"/logs/log_crawler.txt"), true);
			logsFile.write(start);
			logsFile.write(System.getProperty("line.separator"));
		} catch (IOException ioe) {
			System.out.println(dateFormat.format(new Date()) + " - Error: cannot write the log file.\n"
					+ "> Please check your file system permissions.");
			System.exit(1);
		}

		// FLASH COOKIES
		findAndInitializeFlashCookiesStats();

		// FIREFOX COOKIES
		findAndInitializeFirefoxCookiesStats(ffprofile);

		// Manage the signals
		// Note: placed after the check of file permissions because this check is really fast + uses logMessage
		Runtime.getRuntime().addShutdownHook(new Thread()
		{
			@Override
			public void run()
			{
				logMessage("Terminating now...", 1);
				haltDriver();
				deleteUselessFiles(directoryName);
				detailProblematicWebsites();
				writeCookiesStats(directoryName);
				scanner.close();
				closeLogFile();
			}
		});

		// Get the list of websites
		logMessage("Loading the list of websites...", 1);
		WebsitesList websites = new WebsitesList(websitesFile, startIndex, endIndex);
		if(websites.getWebsites().size() == 0) {
			logMessage("Error: the list of websites is empty.", 3);
			logMessage(websites.getStatus(), 2);
			System.exit(1);
		}
		else {
			logMessage("Info: " + websites.getStatus(), 2);
		}

		// Initialize the driver
		logMessage("Initializing the driver...", 1);
		initializeDriver(directoryName, ffprofile, timeout);

		for(Website website : websites.getWebsites()) {
			// Restart Firefox
			if(websitesVisited % restart == 0 && websitesVisited != 0) {
				logMessage("Restarting Firefox...", 1);
				driver.quit();
				initializeDriver(directoryName, ffprofile, timeout);
			}

			boolean success = false;
			int attempt = 1;

			do {
				try {
					logMessage("Crawling website #" + website.getPosition() + " - " + website.getUrl()
							+ " (attempt #" + attempt + ").", 1);
					if(website.getUrl().contains("http")) {
						driver.get(website.getUrl());
					}
					else {
						driver.get("http://" + website.getUrl());
					}

					// Flash cookies
					int flashCookies = countAndDeleteFlashCookies();
					logMessage("Number of Flash cookies found and deleted: " + flashCookies, 2);
					flashCookiesPerWebsite.put(website.getUrl(), flashCookies);

					// Wait till HAR is exported
					try {
						System.out.println("                        Waiting 8 seconds"
								+ " for the HAR file to be exported...");
						Thread.sleep(8000);
					} catch (InterruptedException e) {
						if(debug) e.printStackTrace();
					}
					success = true;
				} catch (TimeoutException te) {
					logMessage("Error: website " + website.getUrl()
							+ " was not successfully loaded (timeout).", 3);
					attempt++;
					// Add the website to the list of potentially failed websites at the 2nd attempt
					if(attempt == 2) {
						websitesTimeout.add(website.getUrl());
					}
					if(debug) te.printStackTrace();
					// Move to the blank page before retrying to load the website
					try {
						driver.get("about:blank");
						Thread.sleep(5000); // It's necessary to give time to the browser
					} catch (InterruptedException ie) {
						if(debug) ie.printStackTrace();
					}
				} catch (UnreachableBrowserException e) {
					logMessage("Critical error: cannot communicate with the remote browser."
							+ " Don't close Firefox!", 3);
					if(debug) e.printStackTrace();
					System.exit(1);
				} catch (UnhandledAlertException e) {
					logMessage("Error: website " + website.getUrl()
							+ " was not successfully loaded (error).", 3);
					if(debug) e.printStackTrace();
					// Skip the website and consider it as failed
					websitesFailed.add(website.getUrl());
					break;
				}
			} while(attempt <= attempts && !success);
			websitesVisited++;

			// The website failed after several attempts
			if(attempt >= attempts && !success) {
				websitesFailed.add(website.getUrl());
				// Note: Keep the website in the timed out list: can distinguish between the fails and timeouts in the failed list.
			}
		}

		logMessage("Info: the crawling of the websites is done!", 1);
		System.exit(0);
	}

	/**
	 * Writes the statistics about the cookies
	 *
	 * @param directoryName
	 */
	private static void writeCookiesStats(String directoryName) {
		try {
			// Flash cookies
			BufferedWriter flashCookiesFile = new BufferedWriter(new FileWriter(new File(directoryName+"/logs/stats_flash-cookies.csv"), false));

			Map<String, Integer> sortedFlashCookiesStats = sortByValueInDescendingOrder(flashCookiesPerWebsite);

			for(String name : sortedFlashCookiesStats.keySet()) {
				int trackerCount = sortedFlashCookiesStats.get(name);
				if(trackerCount != 0) {
					flashCookiesFile.write(name + "," + trackerCount);
					flashCookiesFile.newLine();
				}
			}
			flashCookiesFile.close();

		} catch (IOException e) {
			logMessage("Error: cannot write the statistics files about the cookies!", 3);
			if(debug) e.printStackTrace();
		}
	}

	/**
	 * Checks if the directories exist and creates them if needed
	 *
	 * @param directoryName the directory to check
	 * @return true if the directories exists (or have been created), false otherwise
	 */
	public static boolean checkDirectories(String directoryName) {
		boolean directoriesOK = true;

		File directory = new File(directoryName);
		File logsDirectory = new File(directoryName + "/logs/");

		// The directory does not exist: create both the directory and the subdirectories
		if(!directory.isDirectory()) {
			// Main directory
			if(directory.mkdirs()) {
				System.out.println("Info: a directory named \"" + directoryName + "\" has been created.");
			}
			else {
				directoriesOK = false;
			}
			// Logs subdirectory
			if(logsDirectory.mkdirs()) {
				System.out.println("      a subdirectory named \"logs\" has also been created.");
			}
			else {
				directoriesOK = false;
			}
		}
		// The directory already exists: check if the subdirectories also exists
		else {
			// Logs subdirectory
			if(!logsDirectory.isDirectory()) {
				if(logsDirectory.mkdirs()) {
					System.out.println("Info: a subdirectory named \"logs\" has been created.");
				}
				else {
					directoriesOK = false;
				}
			}
			else {
				System.out.println("Info: the logs will be saved in the subdirectory named \"logs\".");
			}
		}

		return directoriesOK;
	}

	/**
	 * Gets the Flash cookies folder
	 */
	private static void findAndInitializeFlashCookiesStats() {
		String baseFlashFolder = System.getProperty("user.home") + "/.macromedia/Flash_Player/#SharedObjects/";
		File allFolders[] = new File(baseFlashFolder).listFiles(new FileFilter() {
			public boolean accept(File file) {
				return file.isDirectory();
			}
		});

		File cookieFlashFolder = null;

		if(allFolders.length > 1) {
			System.out.println("Multiple folders found for Flash cookies !");
			while(cookieFlashFolder == null) {
				// Show the folders
				int i = 0;
				System.out.println("-1) exit");
				for(File folder : allFolders) {
					try {
						System.out.println(" " + i + ") " + folder.getCanonicalPath());
					} catch (IOException e) {
						System.out.println("Error: cannot retrieve the folders.");
					}
					i++;
				}
				// Ask which one to choose
				System.out.print("Which one to choose? ");
				int value = 0;
				boolean isInteger = false;
				try {
					value = scanner.nextInt();
					isInteger = true;
				} catch (java.util.InputMismatchException ime) {
					System.out.println("Please write a number!");
					scanner.nextLine(); // Clean the buffer
				}
				if(isInteger) {
					if(value == -1) {
						System.exit(1);
					}
					else if(value < 0 || value > allFolders.length-1) {
						System.out.println("Wrong choice!");
					}
					else {
						cookieFlashFolder = allFolders[value];
					}
				}
			}
		}
		else {
			cookieFlashFolder = allFolders[0];
		}
		try {
			flashCookiesPath = cookieFlashFolder.getCanonicalPath();
		} catch (IOException ioe) {
			flashCookiesPath = cookieFlashFolder.getAbsolutePath();
		}
		logMessage("Flash cookies folder: " + flashCookiesPath, 0);
		flashCookiesPerWebsite = new HashMap<String, Integer>();

		// Delete the Flash cookies before starting the crawl
		logMessage("Number of Flash cookies found and deleted: " + countAndDeleteFlashCookies(), 2);
	}

	/**
	 * Gets the Firefox cookies folder
	 *
	 * @param ffprofile the Firefox profile
	 */
	private static void findAndInitializeFirefoxCookiesStats(String ffprofile) {
		String baseFirefoxFolder = System.getProperty("user.home") + "/.mozilla/firefox/";

		String profileFolder = null;
		try {
			BufferedReader profilesReader = new BufferedReader(new FileReader(baseFirefoxFolder + "profiles.ini"));
			String line;
			while ((line = profilesReader.readLine()) != null) {
				if(line.equals("Name=" + ffprofile)) {
					line = profilesReader.readLine(); // Skip IsRelative
					line = profilesReader.readLine();
					profileFolder = line.substring(5, line.length()); // Path
					break;
				}
			}
			profilesReader.close();
		} catch (Exception e) {
			logMessage("Error: cannot find Firefox profiles!", 3);
			if(debug) e.printStackTrace();
		}

		firefoxCookiesDB = baseFirefoxFolder + profileFolder + "/cookies.sqlite";
		logMessage("Firefox cookies database: " + firefoxCookiesDB, 0);

		// Delete the Firefox cookies before starting the crawler
		logMessage("Number of Firefox cookies found and deleted: " + countAndDeleteFirefoxCookies(), 2);
	}

	/**
	 * Counts and deletes the Flash cookies
	 *
	 * @return the number of Flash cookies deleted
	 */
	public static int countAndDeleteFlashCookies() {
		Path directory = Paths.get(flashCookiesPath);
		String pattern = "*.sol";

		CounterAndDeleterFileVisitor fileVisitor = new CounterAndDeleterFileVisitor(directory, pattern);
		try {
			Files.walkFileTree(directory, fileVisitor);
		} catch (IOException ioe) {
			System.out.println("A problem occurred while accessing the Flash cookies folder!");
			ioe.printStackTrace();
		}
		return fileVisitor.done();
	}

	// Cannot use this method while Firefox is running because the cookies.sqlite database is updated at the exit of Firefox.
	/**
	 * Counts and deletes the Firefox cookies
	 *
	 * @return the number of Firefox cookies deleted
	 */
	public static int countAndDeleteFirefoxCookies() {
		int count = 0;
		try {
			Class.forName("org.sqlite.JDBC");
		} catch (ClassNotFoundException cnfe) {
			logMessage("Cannot use sqlite-jdbc!", 3);
		}

		Connection connection = null;
		try {
			connection = DriverManager.getConnection("jdbc:sqlite:/" + firefoxCookiesDB);
			Statement statement = connection.createStatement();
			statement.setQueryTimeout(10);

			ResultSet rs = statement.executeQuery("SELECT Count(*) AS count FROM moz_cookies");
			count = rs.getInt("count");

			statement.executeUpdate("delete from moz_cookies");
		} catch (SQLException e) {
			logMessage("Cannot get the number of cookies in the Firefox cookies database!", 3);
		}
		finally {
			try {
				if(connection != null) connection.close();
			} catch(SQLException e) {
				// connection close failed.
				logMessage("Connection to the Firefox cookies database was not closed successfully!", 3);
			}
		}
		return count;
	}

	/**
	 * Orders a Map in a descending order
	 *
	 * @param mapToSort the map to sort
	 * @return a LinkedHashMap containing the values of the map
	 */
	public static LinkedHashMap<String, Integer> sortByValueInDescendingOrder (Map<String, Integer> mapToSort) {
		List<Map.Entry<String, Integer>> entries = new LinkedList<Map.Entry<String, Integer>>(mapToSort.entrySet());
		Collections.sort(entries, new Comparator<Map.Entry<String, Integer>>() {
			@Override
			public int compare(Entry<String, Integer> o1, Entry<String, Integer> o2) {
				return o2.getValue().compareTo(o1.getValue());
			}
		});

		LinkedHashMap<String, Integer> sortedMap = new LinkedHashMap<String, Integer>();
		for(Map.Entry<String, Integer> entry: entries){
			sortedMap.put(entry.getKey(), entry.getValue());
		}

		return sortedMap;
	}

	/**
	 * Initialize the driver.
	 *
	 * @param directoryName the directory in which the files will be written.
	 * @param ffprofile the Firefox profile to use
	 */
	public static void initializeDriver(String directoryName, String ffprofile, int timeout) {
		try {
			// Configure it as a desired capability
			FirefoxProfile profile = new ProfilesIni().getProfile(ffprofile);
			profile.setAcceptUntrustedCertificates(true);
			profile.setAssumeUntrustedCertificateIssuer(true);
			DesiredCapabilities capabilities = new DesiredCapabilities();
			capabilities.setCapability(FirefoxDriver.PROFILE, profile);

			// ----- Firebug + NetExport -----
			// Set default Firefox preferences
			profile.setPreference("app.update.enabled", false);
			String domain = "extensions.firebug.";

			// Set default Firebug preferences
			profile.setPreference(domain + "allPagesActivation", "on");
			profile.setPreference(domain + "breakOnErrors", false);
			profile.setPreference(domain + "showBreakNotification", false);
			profile.setPreference(domain + "defaultPanelName", "net");
			profile.setPreference(domain + "net.enableSites", true);
			profile.setPreference(domain + "console.enableSites", false);
			profile.setPreference(domain + "cookies.enableSites", false);
			profile.setPreference(domain + "script.enableSites", false);
			profile.setPreference(domain + ".currentVersion", "2.0.0"); // Avoid startup screen

			// Set default NetExport preferences
			profile.setPreference(domain + "netexport.alwaysEnableAutoExport", true);
			profile.setPreference(domain + "netexport.compress", false);
			profile.setPreference(domain + "netexport.showPreview", false);
			profile.setPreference(domain + "netexport.defaultLogDir", System.getProperty("user.dir")+"/"+directoryName);

			// Start the browser up
			driver = new FirefoxDriver(capabilities);
			driver.manage().timeouts().pageLoadTimeout(timeout, TimeUnit.SECONDS);

			// Wait till Firebug is loaded
			Thread.sleep(5000);

			logMessage("Info: WebDriver is ready.", 2);
		}
		catch (NullPointerException e) {
			logMessage("Error: the Firefox profile " + ffprofile + " has not been found.", 3);
			if(debug) e.printStackTrace();
			System.exit(1);
		}
		catch (Exception e) {
			logMessage("Error: cannot initialize the driver.", 3);
			if(debug) e.printStackTrace();
			System.exit(1);
		}
	}

	/**
	 * Deletes the useless files.
	 * These are the files generated when visiting the "about:blank" page when retrying another attempt.
	 *
	 * @param directoryName the name of the directory containing the files
	 */
	public static void deleteUselessFiles(String directoryName) {
		for (File file : new File(directoryName).listFiles()) {
			if(file.isFile()) {
				String filename = file.getName();
				if(filename.equals(".har") || filename.substring(1, filename.length()-4).matches("\\d+")) {
					if(!file.delete()) {
						logMessage("Error: cannot delete the following file: " + file.getName(), 3);
					}
				}
			}
		}
	}

	/**
	 * Details the websites for which problems occurred.
	 */
	public static void detailProblematicWebsites() {
		if(!websitesTimeout.isEmpty()) {
			logMessage("", 0);
			logMessage("The " + websitesTimeout.size() + " following website(s) timed out:", 0);
			for(String websitePotentiallyFailed : websitesTimeout) {
				logMessage(websitePotentiallyFailed, 0);
			}
		}
		else {
			logMessage("No website timed out.", 0);
		}

		if(!websitesFailed.isEmpty()) {
			logMessage("", 0);
			logMessage("The " + websitesFailed.size() + " following website(s) failed:", 0);
			for(String websiteFailed : websitesFailed) {
				logMessage(websiteFailed, 0);
			}
		}
		else {
			logMessage("No website failed.", 0);
		}
	}

	/**
	 * Quits the driver.
	 */
	public static void haltDriver() {
		if(driver != null) {
			try {
				driver.quit();
				logMessage("Info: the driver has been halted successfully.", 1);
			} catch (UnreachableBrowserException e) {
				// Do nothing
			} catch (Exception e) {
				logMessage("Error: the driver was not halted successfully.", 1);
				if(debug) e.printStackTrace();
			}
		}
	}

	/**
	 * Prints a message in the console and writes a message in the log file.
	 * @param message the message to print and write.
	 * @param type type of the message:<br>
	 * 		- 0 (normal): just show the message.<br>
	 *		- 1 (show time): add the time before the message.<br>
	 *		- 2 (add spaces): add spaces to offset the lack of time before the message.<br>
	 *		- 3 (focus): add spaces and ">" to focus on a message.<br>
	 */
	public static void logMessage(String message, int type) {
		switch(type) {
		case 1: message = dateFormat.format(new Date()) + " - " + message; break;
		case 2: message = "                        " + message; break;
		case 3: message = "             >>>>>>>>>> " + message; break;
		}

		System.out.println(message);
		try {
			logsFile.write(message);
			logsFile.write(System.getProperty("line.separator"));
			logsFile.flush();
		} catch (IOException ioe) {
			System.out.println("The message was not successfully written in the log file.");
			if(debug) ioe.printStackTrace();
		}
	}

	/**
	 * Closes the logs file.<br>
	 * If a problem occurs, prints a message in the console.
	 */
	public static void closeLogFile() {
		try {
			logsFile.write("----------------------------------------");
			logsFile.write(System.getProperty("line.separator"));
			logsFile.close();
			System.out.println(dateFormat.format(new Date()) + " - Info: log file successfully closed.");
		} catch (IOException ioe) {
			System.out.println(dateFormat.format(new Date()) + " - Error: cannot close the logs file.\n> It may be corrupted.");
			if(debug) ioe.printStackTrace();
		}
	}
}
