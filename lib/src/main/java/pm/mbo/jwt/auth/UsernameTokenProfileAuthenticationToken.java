package pm.mbo.jwt.auth;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class UsernameTokenProfileAuthenticationToken extends AbstractAuthenticationToken {

	private final LoginHeader loginHeader;

	public UsernameTokenProfileAuthenticationToken(final LoginHeader loginHeader) {
		super(null);
		this.loginHeader = loginHeader;
	}

	@Override
	public Object getPrincipal() {
		return loginHeader;
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	public LoginHeader getLoginHeader() {
		return loginHeader;
	}
}
