package pm.mbo.jwt.db.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import pm.mbo.jwt.db.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findByUsername(String username);

}
