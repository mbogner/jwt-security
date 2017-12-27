package pm.mbo.jwt;

import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.PropertySource;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import({JwtConfig.class})
@PropertySource("classpath:/pm/mbo/jwt/jwt.properties")
@Documented
public @interface EnableJwt {
}
