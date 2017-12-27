CREATE TABLE users (
  id            IDENTITY      NOT NULL,
  username      VARCHAR(64)   NOT NULL,
  password_hash VARCHAR(1024) NOT NULL,
  created_at    TIMESTAMP     NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMP     NOT NULL DEFAULT NOW(),
  CONSTRAINT pk_users__id PRIMARY KEY (id),
  CONSTRAINT uc_users__username UNIQUE (username)
);

CREATE TABLE roles (
  id         IDENTITY    NOT NULL,
  name       VARCHAR(64) NOT NULL,
  created_at TIMESTAMP   NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP   NOT NULL DEFAULT NOW(),
  CONSTRAINT pk_roles__id PRIMARY KEY (id),
  CONSTRAINT uc_roles__name UNIQUE (name)
);

CREATE TABLE users_roles (
  id         IDENTITY  NOT NULL,
  user_id    BIGINT    NOT NULL,
  role_id    BIGINT    NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  CONSTRAINT pk_users_roles__id PRIMARY KEY (id),
  CONSTRAINT uc_users_roles__user_id_role_id UNIQUE (user_id, role_id)
);