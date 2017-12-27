package pm.mbo.jwt.auth;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class Keygen {

	@Test
	public void createKey() throws NoSuchAlgorithmException {
		final SecretKey secretKey = MacProvider.generateKey();
		assertThat(secretKey).isNotNull();

		final String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		assertThat(encodedKey).isNotBlank();

		log.debug("key usable for production: {}", encodedKey);
	}

	@Test
	public void readKey() {
		final String keyStr = "s+Bc3DnQiATn4ACetXzMfJpG+GOHnpUWGE6zKQxbvouWBaYiC4AaI8G5zk18VvmFOi3B0ADgLwRtypS6SyAk/Q==";

		final byte[] decodedKey = Base64.getDecoder().decode(keyStr);
		assertThat(decodedKey).isNotNull();

		final SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, SignatureAlgorithm.HS512.getValue());
		assertThat(originalKey).isNotNull();

		final String encodedKeyStr = Base64.getEncoder().encodeToString(originalKey.getEncoded());
		assertThat(encodedKeyStr).isEqualTo(keyStr);
	}

}
