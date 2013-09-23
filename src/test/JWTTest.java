package test;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.junit.Test;
import org.saadahmed.jwt.JWS;
import org.saadahmed.jwt.JWT;
import static org.junit.Assert.*;


public class JWTTest {

	@Test
	public void testCreateJWSFromString() {
		String inputString = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOiIxMzc5ODI1NjY2MzYzIiwieHNyZiI6InZyTzhWY2hmIn0.rfuQzpBcDVX00iG9KFMmVdn-aGy7XOz-Uy6Itpt9oIg";


		JWS jws = new JWS(inputString);

		assertEquals(jws.toString(), inputString);
	}

}
