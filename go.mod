module github.com/cyverse/sftpgo-auth-irods

go 1.18

require (
	github.com/cyverse/go-irodsclient v0.12.8
	github.com/gliderlabs/ssh v0.3.3
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/sftpgo/sdk v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.8.1
	golang.org/x/crypto v0.0.0-20220525230936-793ad666bf5e
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

require (
	github.com/BurntSushi/toml v1.1.0 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/rs/xid v1.3.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
	gopkg.in/yaml.v2 v2.3.0 // indirect
)

replace github.com/sftpgo/sdk => github.com/cyverse/sftpgo-sdk v0.1.3-0.20230906214213-bdb8dbbe543f
