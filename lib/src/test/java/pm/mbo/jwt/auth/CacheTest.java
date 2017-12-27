package pm.mbo.jwt.auth;

import org.ehcache.Cache;
import org.junit.Test;
import pm.mbo.jwt.JwtConfig;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

public class CacheTest {

	private final JwtConfig cacheConfig = new JwtConfig();

	@Test
	public void testCache() {
		final Cache<String, LocalDateTime> nonceCache = cacheConfig.nonceCache(cacheConfig.cacheManager());
		final String nonce1 = "a";

		assertThat(nonceCache.containsKey(nonce1)).isFalse();

		nonceCache.put(nonce1, LocalDateTime.now());

		assertThat(nonceCache.containsKey(nonce1)).isTrue();
	}

}
