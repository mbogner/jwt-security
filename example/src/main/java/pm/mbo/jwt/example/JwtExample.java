package pm.mbo.jwt.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import pm.mbo.jwt.EnableJwt;

@EnableJwt
@SpringBootApplication
public class JwtExample {

	public static void main(final String... args) {
		SpringApplication.run(JwtExample.class, args);
	}

}
