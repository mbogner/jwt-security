package pm.mbo.jwt.db.model;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import pm.mbo.jwt.db.model.meta.AbstractEntity;

import javax.persistence.*;

@Data
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
@Entity
@Table(name = "users_roles", uniqueConstraints = {
	@UniqueConstraint(name = "uc_users_claims__user_id_claim_id", columnNames = {"user_id", "role_id"})
})
public class UserRole extends AbstractEntity<Long> {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(optional = false)
	@JoinColumn(name = "user_id", nullable = false, foreignKey = @ForeignKey(name = "fk_users_roles__user_id"))
	private User user;

	@ManyToOne(optional = false)
	@JoinColumn(name = "role_id", nullable = false, foreignKey = @ForeignKey(name = "fk_users_roles__role_id"))
	private Role role;

}
