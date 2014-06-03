package crawler;

/**
 * Object containing a website.
 *
 */
public class Website {
	private int position;
	private String url;

	/**
	 * Constructor.
	 *
	 * @param position the website's position in the websites file.
	 * @param url the website's URL.
	 */
	public Website(int position, String url) {
		this.position = position;
		this.url = url;
	}

	/**
	 * Gets the position of the website.
	 *
	 * @return an Integer containing the position.
	 */
	public int getPosition() {
		return position;
	}

	/**
	 * Gets the URL of the website.
	 *
	 * @return a String containing the URL.
	 */
	public String getUrl() {
		return url;
	}
}
