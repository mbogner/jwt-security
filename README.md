# jwt-secured-api

Simple json web token implementation for spring boot using jjwt library.

## Configuration

| Property                   | Default           | Required | Description |
| -------------------------- | ----------------- | -------- | ----------- |
| app.nonce.strict           | false             | false    | If set to true a nonce can only be used once until it is removed from cache. |
| app.jwt.key                |                   | *true*   | Private key that is used to sign all JSON web tokens with. Also used to verify signatures. |
| app.jwt.access.validity    | 600               | false    | Number of seconds an access token is valid. |
| app.jwt.refresh.validity   | 3600              | false    | Number of seconds a refresh token is valid. |
| app.timezone               | Europe/Vieanna    | false    | Time zone that is used for time calculations. |
| app.timestamp.strict       | false             | false    | Check timestamp age. Will only log warning if false. |
| app.timestamp.validity     | 10                | false    | Seconds the requested timestamp is allowed to differ from actual server time. |
| app.nonce.poolSize         | 100000            | false    | Number of nonce values to cache. |



Property ... spring boot configuration property key.\
Default ... Default value set in library if nothing found in spring boot config.\
Required ... True if it has to be configured in spring boot configuration.

## Token Types

After a normal login you get different answeres in the response header. An access token
including a timestamp until this token is valid. You also get a refresh token and its own
validity timestamp.

### Access token

The access token is used for normal requests after the login with header values until the
validity timestamp is reached.

### Refresh token

If the validity timestamp of the first access token is reached you an get a new access
token by using the refresh token in place of the access token. The request will include
a new access token if this token is used. After access and refresh token timestamps are
reached you have to do a new login with header values.

## Login Header

You don't need to do a special request for login. If no access token is available you can include the following headers in a normal request.

| Login Header         | Description |
| -------------------- | ----------- |
| X-Auth-Nonce         | Randomly generated string between 32 and 128 characters. |
| X-Auth-Username      | Username. |
| X-Auth-Timestamp     | Actual timestamp in format java.time.format.DateTimeFormatter.ISO_OFFSET_DATE_TIME. |
| X-Auth-Digest        | Sha512Hex(nonce + username + timestamp + Sha512Hex(password)). Algorythm: org.springframework.security.core.token.Sha512DigestUtils.shaHex(String). Password is the plaintext password of the user. |

If the login is valid the following headers are returned.

| Response Header           | Description |
| ------------------------- | ----------- |
| X-Auth-Token-Type         | If this library results in any header response this header should be JWT. Otherwise don't rely on the values. They could come from another library. |
| X-Auth-Access-Token       | The access token that can be used for further requests. |
| X-Auth-Access-Expires-At  | The timestamp until the access token is valid. |
| X-Auth-Refresh-Token      | Refresh token that can be used to get new access tokens. |
| X-Auth-Refresh-Expires-At | The timestamp until the refresh token can be used to get new access tokens. |
| X-Auth-Timestamp-Format   | Name of the time format from java.time.format.DateTimeFormatter. Default: ISO_OFFSET_DATE_TIME |

## Token Login

The X-Auth-Access-Token token from the login response can be used in requests within the Authorization header.

| Header         | Value |
| -------------- | ----- |
| Authorization  | Bearer <value from X-Auth-Access-Token (or X-Auth-Refresh-Token)> |

Make sure to prepend "Bearer " to the token. If you use the refresh token instead of the access token you will get a new
access token with the next response.

Make sure to use the refresh token as usual as possible and keep it safe.

## Schema

Default schema used in the library:

```mysql
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
```