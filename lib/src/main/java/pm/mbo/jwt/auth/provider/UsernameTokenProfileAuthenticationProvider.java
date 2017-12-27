package pm.mbo.jwt.auth.provider;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.ehcache.Cache;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import pm.mbo.jwt.util.DateTimeUtil;
import pm.mbo.jwt.auth.*;
import pm.mbo.jwt.auth.digest.DigestBuilderServer;
import pm.mbo.jwt.db.model.Role;
import pm.mbo.jwt.db.model.User;
import pm.mbo.jwt.db.model.UserRole;
import pm.mbo.jwt.db.repository.UserRepository;

import javax.crypto.SecretKey;
import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.util.*;

@Slf4j
@NoArgsConstructor
@Component
public class UsernameTokenProfileAuthenticationProvider implements AuthenticationProvider {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	@Qualifier("jwt-secured-api")
	private Cache<String, LocalDateTime> nonceCache;

	@Autowired
	@Qualifier("jwt-secured-api")
	private SecretKey jwtSigningKey;

	@Value("${app.nonce.strict}")
	private Boolean appNonceStrict;

	@Value("${app.timestamp.validity}")
	private Integer appTimestampValidity;

	@Value("${app.timestamp.strict}")
	private Boolean appTimestampStrict;

	@Value("${app.jwt.access.validity}")
	private Integer jwtAccessValidityDuration;

	@Value("${app.jwt.refresh.validity}")
	private Integer jwtRefreshValidityDuration;

	@Value("${app.timezone}")
	private String timezone;

	@Transactional
	@Override
	public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
		log.debug("authenticate with {}", this.getClass().getSimpleName());
		final UsernameTokenProfileAuthenticationToken auth = (UsernameTokenProfileAuthenticationToken) authentication;
		final LoginHeader loginHeader = auth.getLoginHeader();
		checkTimestamp(loginHeader.getTimestamp());

		log.debug("try logging in with usernameToken {}", loginHeader);

		final Optional<User> userOptional = userRepository.findByUsername(loginHeader.getUsername());

		if (userOptional.isPresent()) {
			final User user = userOptional.get();
			final String digest = new DigestBuilderServer(
				loginHeader.getNonce(),
				loginHeader.getUsername(),
				loginHeader.getTimestamp(),
				user.getPasswordHash())
				.getDigest();

			log.debug("computed digest: {}", digest);
			log.debug("received digest: {}", loginHeader.getDigest());

			if (digest.equals(loginHeader.getDigest())) {
				if (nonceCache.containsKey(loginHeader.getNonce())) {
					log.warn("nonce {} already used", loginHeader.getNonce());
					if (appNonceStrict) {
						throw new BadCredentialsException("nonce already used");
					}
				}
				nonceCache.put(loginHeader.getNonce(), LocalDateTime.now());

				final List<GrantedAuthority> grantedAuthorities;
				final List<String> roleNames;
				final List<UserRole> userRoles = user.getUserRoles();
				if (null == userRoles || userRoles.isEmpty()) {
					grantedAuthorities = Collections.emptyList();
					roleNames = Collections.emptyList();
				} else {
					grantedAuthorities = new ArrayList<>(userRoles.size());
					roleNames = new ArrayList<>(userRoles.size());
					for (final UserRole userRole : userRoles) {
						final Role role = userRole.getRole();
						log.debug("adding role: {}", role);
						grantedAuthorities.add(() -> role.getName());
						roleNames.add(role.getName());
					}
				}

				final ZonedDateTime dateTime = ZonedDateTime.now(ZoneId.of(timezone));

				final Date now = DateTimeUtil.toDate(dateTime);
				log.debug("now: {}", now);

				final ZonedDateTime accessExpiresDateTime = dateTime.plusSeconds(jwtAccessValidityDuration);
				final Date accessExpires = DateTimeUtil.toDate(accessExpiresDateTime);
				log.debug("accessExpires: {}", accessExpires);

				final ZonedDateTime refreshExpiresDateTime = dateTime.plusSeconds(jwtRefreshValidityDuration);
				final Date refreshExpires = DateTimeUtil.toDate(refreshExpiresDateTime);
				log.debug("refreshExpires: {}", refreshExpires);

				final String accessToken = JwtUtil.createJwt(jwtSigningKey, loginHeader.getUsername(), now, now, accessExpires, roleNames, TokenType.ACCESS);
				final String refreshToken = JwtUtil.createJwt(jwtSigningKey, loginHeader.getUsername(), now, now, refreshExpires, roleNames, TokenType.REFRESH);

				log.debug("#grantedAuthorities: {}", grantedAuthorities.size());
				final AuthenticationWithToken result = new AuthenticationWithToken(new UserPrincipal(user.getUsername(), roleNames), null, grantedAuthorities);
				result.setToken(new TokenResponse(
					accessToken, DateTimeUtil.toDateString(accessExpiresDateTime),
					refreshToken, DateTimeUtil.toDateString(refreshExpiresDateTime)));

				return result;
			}
		}

		log.debug("user not found: {}", loginHeader.getUsername());
		throw new BadCredentialsException("invalid login data");
	}

	private void checkTimestamp(final String timestamp) {
		if (null == timestamp || timestamp.isEmpty()) {
			throw new BadCredentialsException("timestamp missing");
		}

		final ZonedDateTime parsed = ZonedDateTime.parse(timestamp, DateTimeFormatter.ISO_OFFSET_DATE_TIME);
		final ZonedDateTime now = ZonedDateTime.now(parsed.getZone());
		final long diff = Math.abs(ChronoUnit.SECONDS.between(parsed, now));

		log.debug("received timestamp: {}, now: {}, seconds between: {}", parsed, now, diff);
		if(diff > appTimestampValidity) {
			log.warn("received timestamp is older than {} seconds: {} seconds", appTimestampValidity, diff);
			if (appTimestampStrict) {
				throw new BadCredentialsException("timestamp out of range");
			}
		}
	}

	@Override
	public boolean supports(final Class<?> authentication) {
		final boolean supported = UsernameTokenProfileAuthenticationToken.class.isAssignableFrom(authentication);
		log.debug("supporting {}: {}", authentication, supported);
		return supported;
	}

}
