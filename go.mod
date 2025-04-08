module github.com/cyverse/sftpgo-auth-irods

go 1.22

require (
	github.com/cyverse/go-irodsclient v0.17.1
	github.com/gliderlabs/ssh v0.3.3
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/sftpgo/sdk v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/crypto v0.31.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

require (
	github.com/BurntSushi/toml v1.1.0 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/danwakefield/fnmatch v0.0.0-20160403171240-cbb64ac3d964 // indirect
	github.com/dlclark/regexp2 v1.11.5 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/rs/xid v1.3.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2 // indirect
)

replace github.com/sftpgo/sdk => github.com/cyverse/sftpgo-sdk v0.1.3-0.20230913180245-efcf4a8e8628
