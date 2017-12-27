package pm.mbo.jwt.auth;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.RandomStringGenerator;
import org.junit.Test;
import org.springframework.security.core.token.Sha512DigestUtils;
import pm.mbo.jwt.auth.digest.DigestBuilderClient;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

import static org.apache.commons.text.CharacterPredicates.DIGITS;
import static org.apache.commons.text.CharacterPredicates.LETTERS;

@Slf4j
public class UserCredentialer {

	private final RandomStringGenerator rand = new RandomStringGenerator.Builder()
		.withinRange('0', 'z')
		.filteredBy(LETTERS, DIGITS)
		.build();

	@Test
	public void createCredentials() {
		final String pass = rand.generate(32);

		final String hash = Sha512DigestUtils.shaHex(pass);

		log.info("pass: {}", pass);
		log.info("hash: {}", hash);
	}

	@Test
	public void createLoginHeaders() {
		final String nonce = rand.generate(32);
		final String username = "hugo";
		final String timestamp = ZonedDateTime.now(ZoneId.of("Europe/Vienna")).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
		final String password = "h037xVaPrAc9rWCKHlfE9vFJ9hlDDTGH";

		final String digest = new DigestBuilderClient(nonce, username, timestamp, password).getDigest();

		log.info("nonce: {}", nonce);
		log.info("username: {}", username);
		log.info("timestamp: {}", timestamp);
		log.info("digest: {}", digest);
	}

}
