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
@Table(name = "roles", uniqueConstraints = {
	@UniqueConstraint(name = "uc_roles__name", columnNames = {"name"})
})
public class Role extends AbstractEntity<Long> {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotBlank
	@Size(min = 1, max = 64)
	@Column(nullable = false, length = 64)
	private String name;

	@OneToMany(mappedBy = "role")
	private List<UserRole> userRoles;

}
