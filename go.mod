module intel/isecl/go-trust-agent/v4

require (
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.3
	github.com/intel-secl/intel-secl/v4 v4.0.1
	github.com/nats-io/nats.go v1.11.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.6.1
	gopkg.in/yaml.v2 v2.3.0
	intel/isecl/lib/common/v4 v4.0.1
	intel/isecl/lib/tpmprovider/v4 v4.0.1
)

replace (
	github.com/intel-secl/intel-secl/v4 => gitlab.devtools.intel.com/sst/isecl/intel-secl.git/v4 v4.0.1/develop
	intel/isecl/lib/common/v4 => gitlab.devtools.intel.com/sst/isecl/lib/common.git/v4 v4.0.1/develop
	intel/isecl/lib/tpmprovider/v4 => gitlab.devtools.intel.com/sst/isecl/lib/tpm-provider.git/v4 v4.0.1/develop
)
