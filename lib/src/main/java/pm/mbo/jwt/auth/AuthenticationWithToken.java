package pm.mbo.jwt.auth;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.util.Collection;

public class AuthenticationWithToken extends PreAuthenticatedAuthenticationToken {

	public AuthenticationWithToken(UserPrincipal aPrincipal, Object aCredentials, Collection<? extends GrantedAuthority> anAuthorities) {
		super(aPrincipal, aCredentials, anAuthorities);
	}

	public void setToken(final TokenResponse token) {
		setDetails(token);
	}

	public TokenResponse getToken() {
		return (TokenResponse) getDetails();
	}
}
