package pm.mbo.jwt;

import io.jsonwebtoken.SignatureAlgorithm;
import org.ehcache.Cache;
import org.ehcache.CacheManager;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.ehcache.config.builders.CacheManagerBuilder;
import org.ehcache.config.builders.ResourcePoolsBuilder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import pm.mbo.jwt.db.model.User;
import pm.mbo.jwt.db.repository.UserRepository;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.validation.Validation;
import javax.validation.Validator;
import java.time.LocalDateTime;
import java.util.Base64;

@Configuration
@ComponentScan(basePackageClasses = {JwtConfig.class})
@EnableJpaRepositories(basePackageClasses = {UserRepository.class})
@EntityScan(basePackageClasses = {User.class})
public class JwtConfig {

	@Value("${app.jwt.key}")
	private String jwtSigningKeyStr;

	@Value("${app.nonce.poolSize}")
	private Long noncePoolSize;

	@Bean
	@Qualifier("jwt-secured-api")
	public SecretKey jwtSigningKey() {
		final byte[] decodedKey = Base64.getDecoder().decode(jwtSigningKeyStr);
		return new SecretKeySpec(decodedKey, 0, decodedKey.length, SignatureAlgorithm.HS512.getValue());
	}

	@Bean
	@Qualifier("jwt-secured-api")
	public Cache<String, LocalDateTime> nonceCache(final CacheManager cacheManager) {
		return cacheManager.createCache("nonceCache",
			CacheConfigurationBuilder.newCacheConfigurationBuilder(String.class, LocalDateTime.class, ResourcePoolsBuilder.heap(noncePoolSize)));
	}

	@Bean
	@ConditionalOnMissingBean
	public CacheManager cacheManager() {
		final CacheManager cacheManager = CacheManagerBuilder.newCacheManagerBuilder().build();
		cacheManager.init();
		return cacheManager;
	}

	@Bean
	@ConditionalOnMissingBean
	public Validator validator() {
		return Validation.buildDefaultValidatorFactory().getValidator();
	}

}
