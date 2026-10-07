# sftpgo-auth-irods

SFTPGo External Authentication module for iRODS.

SFTPGo runs this program for every login attempt. It authenticates the user
against iRODS and, on success, prints the SFTPGo user to authenticate as,
with the user's iRODS home collection — and optionally a shared collection —
mounted as virtual folders.

## How it works

SFTPGo's external authentication hook passes the login attempt in environment
variables (`SFTPGO_AUTHD_*`) and reads an SFTPGo user, serialized as JSON, from
stdout. A user with an empty username means the authentication failed. See
[SFTPGo's external auth documentation](https://docs.sftpgo.com/latest/external-auth/).

Two authentication methods are supported, and which one runs depends on whether
SFTPGo passed a public key:

**Password.** The password is verified by logging in to iRODS as the user.

**Public key.** The proxy account logs in to iRODS, reads
`/<zone>/home/<user>/.ssh/authorized_keys` and looks for the presented key.
`IRODS_PROXY_USER` and `IRODS_PROXY_PASSWORD` are required for this, because
the user's own credentials are not available during public key authentication.

Either way the response mounts:

| Virtual path | iRODS collection |
| --- | --- |
| `/<username>` | `/<zone>/home/<username>` |
| `/<IRODS_SHARED basename>` | `IRODS_SHARED`, when set |

The root `/` is listable only; each mounted folder is fully writable. If the last
element of `IRODS_SHARED` is the same as the user name, both folders would mount
at the same virtual path, so the shared one is dropped with a warning and the
user keeps their home.

## authorized_keys options

Options on the matching `authorized_keys` line are honoured, following OpenSSH's
`sshd(8)`:

| Option | Effect |
| --- | --- |
| `home="<path>"` | Mount this collection instead of the user's home. An absolute path is used as is, a relative one resolves against the home. |
| `expiry-time="<timespec>"` | Refuse the key after this time. `YYYYMMDD[Z]` and `YYYYMMDDHHMM[SS][Z]` are accepted, plus `YYYY-MM-DD HH:MM:SS`. A trailing `Z` means UTC, otherwise the local time zone applies. |
| `from="<pattern-list>"` | Accept the key only from these addresses. Comma separated, each a CIDR block or an address with `*` and `?` wildcards, and `!` negates. A pattern has to match the whole address. |

A value that cannot be parsed is treated as expired, and a key whose `from=` list
matches nothing is refused.

Because `home=` confines a key to one collection, a key using it gets its own
SFTPGo user named `<username>_<key fingerprint>` so that two keys of the same
user cannot share a home. The user's iRODS identity is unchanged.

`authorized_keys` is read up to 1 MiB. Keys past that point are ignored, with a
warning naming the file's real size.

## Anonymous access

A login as `anonymous`, in any case, authenticates against iRODS with an empty
password and is given no home collection — only `IRODS_SHARED`, if set. A public
key presented for `anonymous` is ignored.

## Configuration

Everything is configured through the hook's environment. Values marked required
are rejected at startup when missing.

### iRODS connection

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `IRODS_HOST` | yes | | |
| `IRODS_PORT` | | `1247` | |
| `IRODS_ZONE` | yes | | |
| `IRODS_AUTH_SCHEME` | | `native` | `native`, `pam` or `pam_for_users` |
| `IRODS_PROXY_USER` | for public keys | | iRODS account used to read `authorized_keys` |
| `IRODS_PROXY_PASSWORD` | for public keys | | |

`pam_for_users` verifies the user's password over PAM but mounts the filesystem
with `native` when a proxy account is configured, so that the proxy credentials
are used for data access.

### Transport security

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `IRODS_REQUIRE_CS_NEGOTIATION` | for PAM | `false` | |
| `IRODS_CS_NEGOTIATION_POLICY` | | `CS_NEG_DONT_CARE` | `CS_NEG_REFUSE`, `CS_NEG_REQUIRE` or `CS_NEG_DONT_CARE` |
| `IRODS_SSL_CA_CERT_PATH` | for SSL | | A PEM file or a directory of them. Empty uses the system roots. |
| `IRODS_SSL_ALGORITHM` | for SSL | | e.g. `AES-256-CBC` |
| `IRODS_SSL_KEY_SIZE` | for SSL | | e.g. `32` |
| `IRODS_SSL_SALT_SIZE` | for SSL | | e.g. `8` |
| `IRODS_SSL_HASH_ROUNDS` | for SSL | | e.g. `16` |
| `IRODS_SSL_VERIFY_SERVER` | | `none` | `none`, `cert` or `hostname` |

The SSL settings are required when the negotiation policy is `CS_NEG_REQUIRE`,
and whenever the auth scheme is `pam` or `pam_for_users`.

An unrecognized negotiation policy is rejected rather than accepted, because
go-irodsclient silently maps an unknown value to a plain TCP connection.

`IRODS_SSL_VERIFY_SERVER` defaults to `none`, which does not check the iRODS
server certificate. Only `hostname` verifies it: go-irodsclient treats `cert`
the same as `none`, and selecting it logs a warning. Note that this covers this
hook's own connections; SFTPGo's data connections have no equivalent setting.

### Mounts and the SFTPGo user

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `IRODS_SHARED` | | | Collection to mount alongside the home, e.g. `/iplant/home/shared` |
| `SFTPGO_HOME_PATH` | | `/srv/sftpgo/data` | Local directory SFTPGo maps the user under |
| `SFTPGO_AUTH_CACHE_TIME` | | `300` | Seconds SFTPGo may reuse a successful authentication. `0` falls back to the default. |

`SFTPGO_AUTH_CACHE_TIME` is returned to SFTPGo as `external_auth_cache_time`, so
SFTPGo answers repeat logins from its own cache instead of running this hook and
an iRODS login again. A revoked password or public key keeps working until the
entry expires, so keep it short.

### Virtual folder registration

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `SFTPGO_API_BASE_URL` | | | Base URL of the running SFTPGo's admin UI port, e.g. `http://127.0.0.1:8022` |
| `SFTPGO_API_KEY` | | | An API key created in that admin UI |

When both are set, each virtual folder is created through SFTPGo's REST API
before the response is returned. They have to be set together.

`SFTPGO_API_BASE_URL` points back at the SFTPGo instance this hook is
authenticating for. The REST API is served by the same `httpd` binding as the
web admin UI, so it is the **admin UI port**, not a separate one — in
[cyverse/sftpgo-deploy](https://github.com/cyverse/sftpgo-deploy) that is
`SFTPGO_ADMIN_UI_PORT`, `8022` by default. Give the scheme that binding uses:
`http://` unless `enable_https` is on. The binding also needs
`enable_rest_api: true`, which is the default in that deployment. Append no path;
`/api/v2/...` is added by this program.

`SFTPGO_API_KEY` has to be obtained from that same admin UI: log in as an
administrator and create an API key, then copy it into the hook's environment.
SFTPGo shows the key only once, when it is created, and stores only a hash
afterwards, so it cannot be read back later — create a new one if it is lost.
The key is sent in the `X-SFTPGO-API-KEY` header.

### Logging

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `SFTPGO_LOG_DIR` | | `/tmp` | `sftpgo_auth_irods.log`, rotated at 50 MB |

### Passed in by SFTPGo

`SFTPGO_AUTHD_USERNAME`, `SFTPGO_AUTHD_PASSWORD`, `SFTPGO_AUTHD_PUBLIC_KEY` and
`SFTPGO_AUTHD_IP`. The username and the IP are always required, along with at
least one of the password and the public key.

## Wiring it into SFTPGo

Point `external_auth_hook` at the binary and set `external_auth_scope` to `3`,
which is passwords (`1`) and public keys (`2`):

```json
{
  "data_provider": {
    "external_auth_hook": "/usr/local/bin/sftpgo-auth-irods",
    "external_auth_scope": 3
  }
}
```

SFTPGo passes the environment through its `command` section, matched on the
command's path:

```json
{
  "command": {
    "timeout": 30,
    "env": [],
    "commands": [
      {
        "path": "/usr/local/bin/sftpgo-auth-irods",
        "timeout": 30,
        "env": [
          "IRODS_PROXY_USER=proxy_user",
          "IRODS_PROXY_PASSWORD=proxy_password",
          "IRODS_HOST=data.cyverse.org",
          "IRODS_PORT=1247",
          "IRODS_ZONE=iplant",
          "IRODS_REQUIRE_CS_NEGOTIATION=false",
          "IRODS_CS_NEGOTIATION_POLICY=CS_NEG_DONT_CARE",
          "IRODS_AUTH_SCHEME=native",
          "IRODS_SSL_CA_CERT_PATH=",
          "IRODS_SSL_ALGORITHM=AES-256-CBC",
          "IRODS_SSL_KEY_SIZE=32",
          "IRODS_SSL_SALT_SIZE=8",
          "IRODS_SSL_HASH_ROUNDS=16",
          "IRODS_SHARED=/iplant/home/shared",
          "SFTPGO_HOME_PATH=/srv/sftpgo/data"
        ],
        "args": [],
        "hook": ""
      }
    ]
  }
}
```

SFTPGo gives the hook 30 seconds, which is also the timeout this program uses for
its iRODS connections and REST API calls.

[cyverse/sftpgo-deploy](https://github.com/cyverse/sftpgo-deploy) builds this
configuration from a template; see `sftpgo/scripts/sftpgo.json.template` there
for a complete example.

That template leaves out the variables the hook has a usable default for, or
that are off unless configured. Add them to the same `env` list to use them:

```json
"SFTPGO_LOG_DIR=/var/log/sftpgo",
"SFTPGO_AUTH_CACHE_TIME=300",
"IRODS_SSL_VERIFY_SERVER=hostname",
"SFTPGO_API_BASE_URL=http://127.0.0.1:8022",
"SFTPGO_API_KEY=the-key-from-the-admin-ui"
```

## Building

```bash
make build      # bin/sftpgo-auth-irods
make test       # go test ./...
```

Released archives for linux on `386`, `amd64`, `arm` and `arm64` are attached to
each GitHub release.

## Checking the configuration

Running the binary with the environment set performs a real authentication and
prints the response, which is the quickest way to confirm a deployment:

```bash
SFTPGO_AUTHD_USERNAME=someuser \
SFTPGO_AUTHD_PASSWORD=secret \
SFTPGO_AUTHD_IP=10.0.0.1 \
IRODS_HOST=data.cyverse.org IRODS_ZONE=iplant \
  ./bin/sftpgo-auth-irods
```

It exits `0` with the user on success and `1` with an empty username on failure.
Details go to the log, not to stdout, so that the response stays valid JSON.

`--version` prints the build information.
