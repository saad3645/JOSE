package org.saadahmed.jwt;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.saadahmed.json.JSONException;
import org.saadahmed.json.JSONObject;
import org.saadahmed.json.OrderedJSONObject;

import java.util.*;


/**
 *
 * @author Saad Ahmed
 */
public abstract class JWT {

	public static final String ALG = "alg";
	public static final String JKU = "jku";
	public static final String JWK = "jwk";
	public static final String X5U = "x5u";
	public static final String X5T = "x5t";
	public static final String X5C = "x5c";
	public static final String KID = "kid";
	public static final String TYP = "typ";
	public static final String CTY = "cty";
	public static final String CRIT = "crit";

	public static final String ISS = "iss";
	public static final String SUB = "sub";
	public static final String AUD = "aud";
	public static final String EXP = "exp";
	public static final String NBF = "nbf";
	public static final String IAT = "iat";
	public static final String JTI = "jti";


	// Only HMAC algorithms are supported for now
	public static final Map<String, String> ALGORITHMS = new HashMap<String, String>(){{
		// MAC algorithms
		put("HS1", "HmacSHA1");
		put("HS256", "HmacSHA256");
		put("HS384", "HmacSHA384");
		put("HS512", "HmacSHA512");
		put("none", "none");
	}};


	protected OrderedJSONObject header;
	protected OrderedJSONObject payload;


	protected JWT(OrderedJSONObject header, OrderedJSONObject payload) {
		if (header == null) {
			throw new IllegalArgumentException("Header is null.");
		}

		if (payload == null) {
			throw new IllegalArgumentException("Payload is null.");
		}

		this.header = header;
		this.payload = payload;
	}

	protected JWT(JSONObject header, JSONObject payload) {
		this(new OrderedJSONObject(header), new OrderedJSONObject(payload));
	}

	protected JWT(Map<String, String> header, Map<String, String> payload) {
		this(new OrderedJSONObject(header), new OrderedJSONObject(payload));
	}

	protected JWT(String header, String payload) throws JSONException {
		this(new OrderedJSONObject(header), new OrderedJSONObject(payload));
	}

	protected JWT(String encodedString) throws JSONException {
		if (encodedString == null) {
			throw new IllegalArgumentException("Source is null.");
		}

		String[] array = encodedString.split("\\.");

		if (array.length < 2) {
			throw new IllegalArgumentException("Invalid JWT format.");
		}

		if (array[0].isEmpty()) {
			throw new IllegalArgumentException("Header is empty.");
		}

		if (array[1].isEmpty()) {
			throw new IllegalArgumentException("Payload is empty.");
		}

		this.header = new OrderedJSONObject(StringUtils.newStringUtf8(Base64.decodeBase64(array[0])));
		this.payload = new OrderedJSONObject(StringUtils.newStringUtf8(Base64.decodeBase64(array[1])));
	}


	public boolean hasAlgorithm() {
		return hasHeaderParameter(ALG);
	}

	public String algorithm() {
		return getHeaderParameter(ALG);
	}

	public boolean hasHeaderParameter(String key) {
		if (this.header == null) {
			return false;
		}

		return this.header.has(key);
	}

	public String getHeaderParameter(String key) {
		if (this.header == null) {
			throw new JSONException("Header is null.");
		}

		return this.header.getString(key);
	}

	public boolean hasClaim(String key) {
		if (this.payload == null) {
			return false;
		}

		return this.payload.has(key);
	}

	public String getClaim(String key) {
		if (this.payload == null) {
			throw new JSONException("Payload is null.");
		}

		return this.payload.getString(key);
	}

	protected String encodeBase64UrlSafe() {
		if (header == null) {
			throw new JSONException("Header is null.");
		}

		if (payload == null) {
			throw new JSONException("Payload is null.");
		}

		String header = Base64.encodeBase64URLSafeString(StringUtils.getBytesUtf8(this.header.toString()));
		String payload = Base64.encodeBase64URLSafeString(StringUtils.getBytesUtf8(this.payload.toString()));
		return (header + "." + payload);
	}

	@Override
	public String toString() {
		if (this.header == null || this.payload == null) {
			return "";
		}

		return encodeBase64UrlSafe();
	}

	public static String[] supportedAlgorithms() {
		Iterator<String> itr = ALGORITHMS.keySet().iterator();
		String[] algorithms = new String[ALGORITHMS.size()];

		for (int i = 0; itr.hasNext() && i < algorithms.length; i++) {
			algorithms[i] = itr.next();
		}

		return algorithms;
	}

}
