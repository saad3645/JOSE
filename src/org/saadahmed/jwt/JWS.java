package org.saadahmed.jwt;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.saadahmed.crypto.MacUtils;
import org.saadahmed.json.JSONException;
import org.saadahmed.json.JSONObject;
import org.saadahmed.json.OrderedJSONObject;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;


/**
 *
 * @author Saad Ahmed
 */
public class JWS extends JWT {

	public static final String ALG_NONE = "none";


	private String signature;


	public JWS(OrderedJSONObject header, OrderedJSONObject payload, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		super(header, payload);
		this.signature = sign(key);
	}

	public JWS(JSONObject header, JSONObject payload, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		this(new OrderedJSONObject(header), new OrderedJSONObject(payload), key);
	}

	public JWS(Map<String, String> header, Map<String, String> payload, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		this(new OrderedJSONObject(header), new OrderedJSONObject(payload), key);
	}

	public JWS(String header, String payload, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, JSONException {
		this(new OrderedJSONObject(header), new OrderedJSONObject(payload), key);
	}

	public JWS(String encodedString, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, JSONException {
		super(encodedString);
		this.signature = sign(key);
	}

	public JWS(String encodedString) throws JSONException {
		super(encodedString);

		if (encodedString != null) {
			String[] array = encodedString.split("\\.");

			if (array.length != 3) {
				throw new IllegalArgumentException("Invalid JWS format.");
			}

			this.signature = array[2];
		}
	}


	public String sign(byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		if (header == null) {
			throw new IllegalArgumentException("Header is null.");
		}

		if (!hasAlgorithm()) {
			throw new NoSuchAlgorithmException("\"" + ALG + "\" not present.");
		}

		if (algorithm() == null) {
			throw new NoSuchAlgorithmException("\"" + ALG + "\" is null.");
		}

		if (algorithm().equals(ALG_NONE)) {
			return "";
		}


		if (payload == null) {
			throw new IllegalArgumentException("Payload is null.");
		}

		if (key == null) {
			throw new InvalidKeyException("Key is null.");
		}

		if (!ALGORITHMS.containsKey(algorithm())) {
			throw new NoSuchAlgorithmException("\"" + algorithm() + "\" is not a supported algorithm");
		}

		String data = encodeBase64UrlSafe();
		String algorithm = ALGORITHMS.get(algorithm());

		byte[] signature = MacUtils.compute(algorithm, key, StringUtils.getBytesUtf8(data));
		return Base64.encodeBase64URLSafeString(signature);
	}

	public boolean hasSignature() {
		return (this.signature != null && !this.signature.isEmpty());
	}

	public String getSignature() {
		if (hasSignature()) {
			return this.signature;
		}

		else return "";
	}

	@Override
	public String toString() {
		if (this.header == null || this.payload == null) {
			return "";
		}

		return encodeBase64UrlSafe() + "." + getSignature();
	}



	public static String encode(OrderedJSONObject header, OrderedJSONObject payload, byte[] key) throws InvalidKeyException, NoSuchAlgorithmException {
		return new JWS(header, payload, key).toString();
	}

	public static String encode(JSONObject header, JSONObject payload, byte[] key) throws InvalidKeyException, NoSuchAlgorithmException {
		return new JWS(header, payload, key).toString();
	}

	public static String encode(Map<String, String> header, Map<String, String> payload, byte[] key) throws InvalidKeyException, NoSuchAlgorithmException {
		return new JWS(header, payload, key).toString();
	}

	public static String encode(String header, String payload, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, JSONException {
		return new JWS(header, payload, key).toString();
	}

	public static String encode(String jwt, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, JSONException {
		return new JWS(jwt, key).toString();
	}

	public static String sign(OrderedJSONObject header, OrderedJSONObject payload, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		return new JWS(header, payload, key).getSignature();
	}

	public static String sign(JSONObject header, JSONObject payload, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		return new JWS(header, payload, key).getSignature();
	}

	public static String sign(Map<String, String> header, Map<String, String> payload, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		return new JWS(header, payload, key).getSignature();
	}

	public static String sign(String header, String payload, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException, JSONException {
		return new JWS(header, payload, key).getSignature();
	}

	public static String sign(String jwt, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
		return new JWS(jwt, key).toString();
	}

	public static boolean valid(JWS jws, byte[] key) throws InvalidKeyException {
		try {
			String expectedSignature = jws.sign(key);
			return jws.getSignature().equals(expectedSignature);
		}

		catch (NoSuchAlgorithmException e) {
			return false;
		}

		catch (IllegalArgumentException e) {
			return false;
		}

		catch (JSONException e) {
			return false;
		}
	}

	public static boolean valid(String jws, byte[] key) throws InvalidKeyException {
		return valid(new JWS(jws), key);
	}

}
