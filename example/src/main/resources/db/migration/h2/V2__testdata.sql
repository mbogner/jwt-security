INSERT INTO users (username, password_hash) VALUES
  (
    'hugo',
    // pass: h037xVaPrAc9rWCKHlfE9vFJ9hlDDTGH => Sha512Hex
    'ed70d5dc78abb017453cafab66f64571237693cfabf431b997daafe9fbb54c5464f31adc90f19bd3fbf76ece63116c5f6bb5c5bdb66cadca9ff294110ce923b2',
  );

INSERT INTO roles (name) VALUES
  ('api:read'),
  ('api:write');

INSERT INTO users_roles (user_id, role_id) VALUES
  (
    (SELECT u.id
     FROM users u
     WHERE u.username = 'hugo'),
    (SELECT c.id
     FROM roles c
     WHERE c.name = 'api:read')
  );