package pm.mbo.jwt.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolation;
import javax.validation.Validator;
import java.io.IOException;
import java.util.Set;

@Slf4j
public class AuthenticationFilter extends GenericFilterBean {

	public static final String HEADER_AUTHORIZATION = "Authorization";
	private final AuthenticationManager authenticationManager;
	private final Validator validator;

	public AuthenticationFilter(final AuthenticationManager authenticationManager,
	                            final Validator validator) {
		this.authenticationManager = authenticationManager;
		this.validator = validator;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			final HttpServletRequest req = (HttpServletRequest) request;
			final HttpServletResponse res = (HttpServletResponse) response;

			if (isAuthenticationRequired()) {
				log.debug("########## called filter ############ ({})", req.getRequestURI());
				res.addHeader(this.getClass().getSimpleName(), "done");
				tryAuthentication(req, res, chain);
			} else {
				chain.doFilter(request, response);
			}
		} else {
			log.debug("no http servlet request/response");
			chain.doFilter(request, response);
		}
	}

	private void tryAuthentication(final HttpServletRequest req, final HttpServletResponse res, final FilterChain chain) throws IOException, ServletException {
		try {
			log.debug("try authentication");
			final String authorizationHeader = req.getHeader(HEADER_AUTHORIZATION);
			final AuthenticationWithToken authenticationWithToken;
			if (null == authorizationHeader) {
				authenticationWithToken = processLoginData(res, new LoginHeader(req));
				addLoginHeaderResponse(authenticationWithToken, res);
			} else {
				authenticationWithToken = processAuthorizationHeader(authorizationHeader);
				if (null != authenticationWithToken.getToken()) {
					log.debug("added new access token to header");
					addCommonHeaders(authenticationWithToken, res);
				}
			}
			SecurityContextHolder.getContext().setAuthentication(authenticationWithToken);
			chain.doFilter(req, res);
		} catch (final AuthenticationException exc) {
			log.debug("failed login attempt", exc);
			SecurityContextHolder.clearContext();
			res.sendError(HttpServletResponse.SC_UNAUTHORIZED, exc.getMessage());
		}
	}

	private boolean isAuthenticationRequired() {
		final Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
		if ((existingAuth == null) || !existingAuth.isAuthenticated() || !(existingAuth instanceof AuthenticationWithToken)) {
			return true;
		}
		// current session already authenticated - second access in filter chain
		return false;
	}

	private void addLoginHeaderResponse(final AuthenticationWithToken authenticationWithToken,
	                                    final HttpServletResponse res) {
		final TokenResponse tokenResponse = addCommonHeaders(authenticationWithToken, res);
		res.setHeader(TokenResponse.HEADER_X_AUTH_REFRESH_TOKEN, tokenResponse.getRefreshToken());
		res.setHeader(TokenResponse.HEADER_X_AUTH_REFRESH_EXPIRES_AT, tokenResponse.getRefreshTokenExpiresAt());
	}

	private TokenResponse addCommonHeaders(final AuthenticationWithToken authenticationWithToken,
	                                       final HttpServletResponse res) {
		final TokenResponse tokenResponse = authenticationWithToken.getToken();

		res.setHeader(TokenResponse.HEADER_X_AUTH_TOKEN_TYPE, tokenResponse.getTokenType());
		res.setHeader(TokenResponse.HEADER_X_AUTH_TIMESTAMP_FORMAT, tokenResponse.getTimestampFormat());

		res.setHeader(TokenResponse.HEADER_X_AUTH_ACCESS_TOKEN, tokenResponse.getAccessToken());
		res.setHeader(TokenResponse.HEADER_X_AUTH_ACCESS_EXPIRES_AT, tokenResponse.getAccessTokenExpiresAt());

		return tokenResponse;
	}

	private AuthenticationWithToken processLoginData(final HttpServletResponse res,
	                                                 final LoginHeader loginHeader) throws IOException {
		log.debug("process login headers");

		final Set<ConstraintViolation<LoginHeader>> violations = validator.validate(loginHeader);
		if (!violations.isEmpty()) {
			log.warn("unauthenticated access");
			violations.stream().forEach(v -> log.debug("{} {}", v.getPropertyPath(), v.getMessage()));
			throw new AuthenticationCredentialsNotFoundException("invalid login headers");
		}
		return authenticate(new UsernameTokenProfileAuthenticationToken(loginHeader));
	}

	private AuthenticationWithToken processAuthorizationHeader(final String authorizationHeader) {
		log.debug("process authentication header");
		if (null == authorizationHeader || authorizationHeader.length() < 1) {
			throw new AuthenticationCredentialsNotFoundException("invalid login token");
		}
		return authenticate(new PreAuthenticatedAuthenticationToken(authorizationHeader, null));
	}

	private AuthenticationWithToken authenticate(final Authentication authentication) {
		final AuthenticationWithToken auth = (AuthenticationWithToken) authenticationManager.authenticate(authentication);
		if (null == auth || !auth.isAuthenticated()) {
			throw new InternalAuthenticationServiceException("authentication failed");
		}
		log.debug("authenticated user");
		return auth;
	}

}
