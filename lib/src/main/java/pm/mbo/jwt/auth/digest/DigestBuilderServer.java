package pm.mbo.jwt.auth.digest;

import org.hibernate.validator.constraints.NotBlank;
import org.hibernate.validator.constraints.NotEmpty;
import org.springframework.security.core.token.Sha512DigestUtils;

import java.util.Arrays;
import java.util.List;

public class DigestBuilderServer {

	@NotEmpty
	protected final List<String> parts;

	public DigestBuilderServer(@NotBlank final String nonce,
	                           @NotBlank final String username,
	                           @NotBlank final String timestamp,
	                           @NotBlank final String passwordHash) {
		this.parts = Arrays.asList(nonce, username, timestamp, passwordHash);
	}

	public String getDigest() {
		return Sha512DigestUtils.shaHex(createBuffer().toString());
	}

	public int getLength() {
		return parts.stream().mapToInt(p -> p.length()).sum();
	}

	protected StringBuffer createBuffer() {
		final StringBuffer buffer = new StringBuffer(getLength());
		parts.forEach(p -> buffer.append(p));
		return buffer;
	}

}
