package parser;

import java.io.FileReader;
import java.io.IOException;
//import java.net.URL;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Object containing a list of trackers.
 *
 */
public class RegexGhostery {
	private Map<String, String> regex;
	private int bugsVersion;
	private boolean success;

	/**
	 * Constructor.
	 */
	public RegexGhostery(boolean debug, String ghosteryFile) {
		regex = new HashMap<String, String>();
		loadTrackers(debug, ghosteryFile);
	}

	/**
	 *
	 * @return the Map containing the trackers patterns as keys and the trackers names as values.
	 */
	public Map<String, String> getRegex() {
		return regex;
	}

	/**
	 *
	 * @return the version of the bugs file
	 */
	public int getBugsVersion() {
		return bugsVersion;
	}

	/**
	 *
	 * @return true if the bugs file has been successfully loaded
	 */
	public boolean isSuccess() {
		return success;
	}

	/**
	 * Loads the list of trackers from the Ghostery website.
	 *
	 * Fill up the Map "regex",
	 * writes the current version of the file in the integer "bugsVersion" and
	 * indicates if the process finished successfully in the boolean "success".
	 */
	private void loadTrackers(boolean debug, String ghosteryFile) {
		try {
			//URL url = new URL("https://www.ghostery.com/update/bugs?format=json");
			ObjectMapper mapper = new ObjectMapper();
			JsonNode rootNode = mapper.readTree(new FileReader(ghosteryFile));

			Iterator<JsonNode> bugsElements = rootNode.get("bugs").iterator();
			while (bugsElements.hasNext()) {
				JsonNode bug = bugsElements.next();
				String pattern = bug.get("pattern").asText().replace("\\", ""); // Remove the backslashes
				String name = bug.get("name").asText().replace(",", " "); // Remove the commas
				regex.put(pattern, name);
			}

			success = true;
			bugsVersion = rootNode.get("bugsVersion").intValue();
		}
		catch (IOException e) {
			if(debug) e.printStackTrace();
			success = false;
		}
	}
}
