package pm.mbo.jwt.auth;

import lombok.Value;
import org.hibernate.validator.constraints.NotBlank;

import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.Size;

@Value
public class LoginHeader {

	public static final String HEADER_X_AUTH_NONCE = "X-Auth-Nonce";
	public static final String HEADER_X_AUTH_USERNAME = "X-Auth-Username";
	public static final String HEADER_X_AUTH_TIMESTAMP = "X-Auth-Timestamp";
	public static final String HEADER_X_AUTH_DIGEST = "X-Auth-Digest";

	@NotBlank
	@Size(min = 32, max = 128)
	private final String nonce;

	@NotBlank
	private final String username;

	@NotBlank
	private final String timestamp;

	@NotBlank
	private final String digest; // sha256(nonce + username + timestamp + password)

	public LoginHeader(final HttpServletRequest request) {
		this.nonce = request.getHeader(HEADER_X_AUTH_NONCE);
		this.username = request.getHeader(HEADER_X_AUTH_USERNAME);
		this.timestamp = request.getHeader(HEADER_X_AUTH_TIMESTAMP);
		this.digest = request.getHeader(HEADER_X_AUTH_DIGEST);
	}
}
