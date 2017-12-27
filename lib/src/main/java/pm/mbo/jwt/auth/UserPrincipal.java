package pm.mbo.jwt.auth;

import lombok.Value;

import java.util.List;

@Value
public class UserPrincipal {

	private final String username;

	private final List<String> roles;

}
