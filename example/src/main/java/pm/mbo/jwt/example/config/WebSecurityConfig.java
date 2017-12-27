package pm.mbo.jwt.example.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import pm.mbo.jwt.auth.AuthenticationFilter;
import pm.mbo.jwt.auth.provider.TokenAuthenticationProvider;
import pm.mbo.jwt.auth.provider.UsernameTokenProfileAuthenticationProvider;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Validator;

@Configuration
@EnableWebSecurity
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private Validator validator;

	@Autowired
	private UsernameTokenProfileAuthenticationProvider usernameTokenProfileAuthenticationProvider;

	@Autowired
	private TokenAuthenticationProvider tokenAuthenticationProvider;

	@Bean
	public AuthenticationFilter authenticationFilter() throws Exception {
		return new AuthenticationFilter(authenticationManager(), validator);
	}

	@Override
	protected void configure(final HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.anonymous().disable();
		http.headers().frameOptions().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		http.authorizeRequests().anyRequest().authenticated();

		http.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint());
		http.addFilterBefore(authenticationFilter(), UsernamePasswordAuthenticationFilter.class);
	}

	@Autowired
	public void configureGlobal(final AuthenticationManagerBuilder auth) throws Exception {
		auth
			.authenticationProvider(usernameTokenProfileAuthenticationProvider)
			.authenticationProvider(tokenAuthenticationProvider);
	}

	@Bean
	public AuthenticationEntryPoint authenticationEntryPoint() {
		return (request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
	}

}