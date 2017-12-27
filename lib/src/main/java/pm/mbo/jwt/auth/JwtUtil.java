package pm.mbo.jwt.auth;

import io.jsonwebtoken.CompressionCodecs;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.crypto.SecretKey;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public final class JwtUtil {

	public static Date createExpireDate(final Calendar start, final Integer seconds) {
		final Date now = start.getTime();

		start.add(Calendar.SECOND, seconds);
		final Date expires = start.getTime();

		// reset
		start.setTime(now);

		return expires;
	}

	public static String createJwt(final SecretKey jwtSigningKey,
	                               final String username,
	                               final Date issuedAt,
	                               final Date notBefore,
	                               final Date expiration,
	                               final List<String> roleNames,
	                               final TokenType tokenType) {
		return Jwts.builder()
		           .setSubject(username)
		           .compressWith(CompressionCodecs.DEFLATE)
		           .signWith(SignatureAlgorithm.HS256, jwtSigningKey)
		           .claim("type", tokenType.toString())
		           .claim("roles", roleNames)
		           .setId(UUID.randomUUID().toString())
		           .setIssuedAt(issuedAt)
		           .setNotBefore(notBefore)
		           .setExpiration(expiration)
		           .compact();
	}

	private JwtUtil() {
		throw new IllegalStateException();
	}
}
