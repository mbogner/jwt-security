package pm.mbo.jwt.auth;

import lombok.Value;

@Value
public class TokenResponse {

	public static final String HEADER_X_AUTH_TOKEN_TYPE = "X-Auth-Token-Type";
	public static final String HEADER_X_AUTH_ACCESS_TOKEN = "X-Auth-Access-Token";
	public static final String HEADER_X_AUTH_ACCESS_EXPIRES_AT = "X-Auth-Access-Expires-At";
	public static final String HEADER_X_AUTH_REFRESH_TOKEN = "X-Auth-Refresh-Token";
	public static final String HEADER_X_AUTH_REFRESH_EXPIRES_AT = "X-Auth-Refresh-Expires-At";
	public static final String HEADER_X_AUTH_TIMESTAMP_FORMAT = "X-Auth-Timestamp-Format";

	private final String tokenType = "JWT";
	private final String accessToken;
	private final String accessTokenExpiresAt;
	private final String refreshToken;
	private final String refreshTokenExpiresAt;
	private final String timestampFormat = "ISO_OFFSET_DATE_TIME";

}
