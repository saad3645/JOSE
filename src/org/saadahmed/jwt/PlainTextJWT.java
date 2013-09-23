package org.saadahmed.jwt;


import org.saadahmed.json.JSONException;
import org.saadahmed.json.JSONObject;
import org.saadahmed.json.OrderedJSONObject;

import java.util.Map;


/**
 *
 * @author Saad Ahmed
 */
public class PlainTextJWT extends JWT {

	public PlainTextJWT(OrderedJSONObject header, OrderedJSONObject payload) {
		super(header, payload);
	}

	public PlainTextJWT(JSONObject header, JSONObject payload) {
		super(header, payload);
	}

	public PlainTextJWT(Map<String, String> header, Map<String, String> payload) {
		super(header, payload);
	}

	public PlainTextJWT(String header, String payload) throws JSONException {
		super(header, payload);
	}

	public PlainTextJWT(String encodedString) throws JSONException {
		super(encodedString);
	}


	public static String encode(OrderedJSONObject header, OrderedJSONObject payload) {
		return new PlainTextJWT(header, payload).toString();
	}

	public static String encode(JSONObject header, JSONObject payload) {
		return new PlainTextJWT(header, payload).toString();
	}

	public static String encode(Map<String, String> header, Map<String, String> payload) {
		return new PlainTextJWT(header, payload).toString();
	}

	public static String encode(String header, String payload) throws JSONException {
		return new PlainTextJWT(header, payload).toString();
	}
}
