module intel/isecl/go-trust-agent/v4

go 1.17

require (
	github.com/google/uuid v1.2.0
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/intel-secl/intel-secl/v4 v4.2.0-Beta
	github.com/nats-io/nats.go v1.11.1-0.20210623165838-4b75fc59ae30
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.6.1
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110
	gopkg.in/yaml.v2 v2.4.0
	intel/isecl/lib/common/v4 v4.2.0-Beta
	intel/isecl/lib/tpmprovider/v4 v4.2.0-Beta
)

require (
	github.com/Waterdrips/jwt-go v3.2.1-0.20200915121943-f6506928b72e+incompatible // indirect
	github.com/cloudflare/cfssl v1.5.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/google/certificate-transparency-go v1.0.21 // indirect
	github.com/nats-io/nkeys v0.3.0 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/objx v0.1.1 // indirect
	golang.org/x/crypto v0.0.0-20210616213533-5ff15b29337e // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)

replace (
	intel/isecl/lib/common/v4 => github.com/intel-secl/common/v4 v4.2.0-Beta
	intel/isecl/lib/tpmprovider/v4 => github.com/intel-secl/tpm-provider/v4 v4.2.0-Beta
)
