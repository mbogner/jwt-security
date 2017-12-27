package pm.mbo.jwt.auth.provider;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Component;
import pm.mbo.jwt.util.DateTimeUtil;
import pm.mbo.jwt.auth.*;

import javax.crypto.SecretKey;
import javax.transaction.Transactional;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
public class TokenAuthenticationProvider implements AuthenticationProvider {

	private static final String BEARER = "Bearer ";

	@Autowired
	@Qualifier("jwt-secured-api")
	private SecretKey jwtSigningKey;

	@Value("${app.jwt.access.validity}")
	private Integer jwtAccessValidityDuration;

	@Value("${app.timezone}")
	private String timezone;

	@Transactional
	@Override
	public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
		log.debug("authenticate with {}", this.getClass().getSimpleName());
		if (null != authentication && authentication instanceof PreAuthenticatedAuthenticationToken
			&& null != authentication.getPrincipal() && authentication.getPrincipal() instanceof String) {
			final PreAuthenticatedAuthenticationToken auth = (PreAuthenticatedAuthenticationToken) authentication;

			String auththoken = ((String) auth.getPrincipal()).trim();
			if (auththoken.startsWith(BEARER)) {
				auththoken = auththoken.replaceFirst(BEARER, "");
				log.debug("received jwt: {}", auththoken);

				try {
					final Jws<Claims> jwsClaims = Jwts.parser()
					                                  .setSigningKey(jwtSigningKey)
					                                  .parseClaimsJws(auththoken);
					final Claims body = jwsClaims.getBody();

					final String id = body.getId();
					final String tokenTypeStr = body.get("type", String.class);
					if (null == tokenTypeStr) {
						throw new BadCredentialsException("type not set");
					}
					final TokenType tokenType = TokenType.valueOf(tokenTypeStr);

					final String username = body.getSubject();
					final Date issuedAt = body.getIssuedAt();
					final Date notBefore = body.getNotBefore();
					final Date expiration = body.getExpiration();
					final List<String> roles = body.get("roles", List.class);

					log.debug("id: {}, tokenType: {}, username: {}, issuedAt: {}, notBefore: {}, expiration: {}, roles: {}",
						id, tokenType, username, issuedAt, notBefore, expiration, roles);

					final List<GrantedAuthority> grantedAuthorities;
					if (null == roles || roles.isEmpty()) {
						grantedAuthorities = Collections.emptyList();
					} else {
						grantedAuthorities = new ArrayList<>(roles.size());
						for (final String role : roles) {
							grantedAuthorities.add(() -> role);
						}
					}

					log.debug("login successful for {}", username);
					final AuthenticationWithToken authToken = new AuthenticationWithToken(new UserPrincipal(username, roles), null, grantedAuthorities);
					if (TokenType.REFRESH == tokenType) {

						final ZonedDateTime dateTime = ZonedDateTime.now(ZoneId.of(timezone));
						final Date now = DateTimeUtil.toDate(dateTime);

						final ZonedDateTime accessExpiresDateTime = dateTime.plusSeconds(jwtAccessValidityDuration);
						final Date expireDate = DateTimeUtil.toDate(accessExpiresDateTime);

						final String accessToken = JwtUtil.createJwt(jwtSigningKey, username, now, now, expireDate, roles, TokenType.ACCESS);
						authToken.setToken(new TokenResponse(accessToken, DateTimeUtil.toDateString(accessExpiresDateTime), null, null));
						log.debug("added new access token to result");
					}
					return authToken;
				} catch (final ExpiredJwtException exc) {
					throw new BadCredentialsException("token expired");
				} catch (final JwtException jwtExc) {
					log.debug(jwtExc.getMessage(), jwtExc);
					throw new BadCredentialsException("invalid login token");
				}
			}
		}

		throw new BadCredentialsException("invalid login data");
	}

	@Override
	public boolean supports(final Class<?> authentication) {
		final boolean supported = PreAuthenticatedAuthenticationToken.class.isAssignableFrom(authentication);
		log.debug("supporting {}: {}", authentication, supported);
		return supported;
	}

}
