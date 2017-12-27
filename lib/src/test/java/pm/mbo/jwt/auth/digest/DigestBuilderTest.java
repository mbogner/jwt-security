package pm.mbo.jwt.auth.digest;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.token.Sha512DigestUtils;

import static org.assertj.core.api.Assertions.assertThat;

public class DigestBuilderTest {

	private DigestBuilderClient client;
	private DigestBuilderServer server;

	private final String nonce = "nonce";
	private final String username = "username";
	private final String timestamp = "2017-12-09T17:20:26.697+01:00"; // ISO 8601
	private final String password = "password";
	private String passwordHash;

	@Before
	public void setUp() throws Exception {
		client = new DigestBuilderClient(nonce, username, timestamp, password);
		passwordHash = Sha512DigestUtils.shaHex(password);
		server = new DigestBuilderServer(nonce, username, timestamp, passwordHash);
	}

	@Test
	public void testDigestEquivalence() {
		final String clientResult = client.getDigest();
		final String serverResult = server.getDigest();
		assertThat(clientResult).isEqualTo(serverResult);
	}

	@Test
	public void testLengthEquivalence() {
		final int digestLength = nonce.length() + username.length() + timestamp.length() + passwordHash.length();
		assertThat(server.getLength()).isEqualTo(client.getLength()); // same result
		assertThat(client.getLength()).isEqualTo(digestLength); // expected
	}

}