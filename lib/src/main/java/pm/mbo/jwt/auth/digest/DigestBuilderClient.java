package pm.mbo.jwt.auth.digest;

import org.hibernate.validator.constraints.NotBlank;
import org.springframework.security.core.token.Sha512DigestUtils;

public class DigestBuilderClient extends DigestBuilderServer {

	public DigestBuilderClient(@NotBlank final String nonce,
	                           @NotBlank final String username,
	                           @NotBlank final String timestamp,
	                           @NotBlank final String password) {
		super(nonce, username, timestamp, Sha512DigestUtils.shaHex(password));
	}

}
