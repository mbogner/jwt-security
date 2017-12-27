package pm.mbo.jwt.db.model;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.hibernate.validator.constraints.NotBlank;
import pm.mbo.jwt.db.model.meta.AbstractEntity;

import javax.persistence.*;
import javax.validation.constraints.Size;
import java.util.List;

@Data
@EqualsAndHashCode(callSuper = true, exclude = {"userRoles"})
@ToString(callSuper = true, exclude = {"userRoles"})
@Entity
@Table(name = "users", uniqueConstraints = {
	@UniqueConstraint(name = "uc_users__username", columnNames = {"username"})
})
public class User extends AbstractEntity<Long> {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotBlank
	@Size(min = 1, max = 64)
	@Column(nullable = false, length = 64)
	private String username;

	@NotBlank
	@Size(min = 1, max = 1024)
	@Column(name = "password_hash", nullable = false, length = 1024)
	private String passwordHash;

	@OneToMany(mappedBy = "user")
	private List<UserRole> userRoles;

}
