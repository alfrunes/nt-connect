module github.com/northerntechhq/nt-connect

go 1.18

replace github.com/urfave/cli/v2 => github.com/mendersoftware/cli/v2 v2.1.1-minimal

require (
	github.com/creack/pty v1.1.21
	github.com/go-ozzo/ozzo-validation/v4 v4.3.0
	github.com/mendersoftware/go-lib-micro v0.0.0-20240304135804-e8e39c59b148
	github.com/pkg/errors v0.9.1
	github.com/satori/go.uuid v1.2.0
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
	github.com/urfave/cli/v2 v2.27.1
	github.com/vmihailenco/msgpack/v5 v5.4.1
	golang.org/x/sys v0.21.0
	nhooyr.io/websocket v1.8.11
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
