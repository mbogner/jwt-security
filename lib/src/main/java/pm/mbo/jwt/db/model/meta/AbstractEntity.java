package pm.mbo.jwt.db.model.meta;

import lombok.Data;

import javax.persistence.Column;
import javax.persistence.MappedSuperclass;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.time.OffsetDateTime;

@Data
@MappedSuperclass
public abstract class AbstractEntity<I extends Serializable> implements Serializable {

	@NotNull
	@Column(name = "created_at", nullable = false, updatable = false)
	private OffsetDateTime createdAt;

	@NotNull
	@Column(name = "updated_at", nullable = false)
	private OffsetDateTime updatedAt;

	@PrePersist
	private void prePerstist() {
		createdAt = OffsetDateTime.now();
		updatedAt = createdAt;
	}

	@PreUpdate
	private void preUpdate() {
		updatedAt = OffsetDateTime.now();
	}

	public abstract I getId();

}
