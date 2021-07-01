package service

import (
	"intel/isecl/go-trust-agent/v4/common"
	"intel/isecl/go-trust-agent/v4/config"
	"intel/isecl/go-trust-agent/v4/constants"
	"strings"

	commLog "github.com/intel-secl/intel-secl/v4/pkg/lib/common/log"
	"github.com/pkg/errors"
)

type TrustAgentService interface {
	Start() error
	Stop() error
}

type NatsParameters struct {
	config.NatsService
	CredentialFile    string
	TrustedCaCertsDir string
}

type WebParameters struct {
	config.WebService
	TLSCertFilePath           string
	TLSKeyFilePath            string
	TrustedJWTSigningCertsDir string
	TrustedCaCertsDir         string
}

type ServiceParameters struct {
	Mode           string
	Web            WebParameters
	Nats           NatsParameters
	RequestHandler common.RequestHandler
}

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func NewTrustAgentService(parameters *ServiceParameters) (TrustAgentService, error) {

	var service TrustAgentService
	var err error

	if strings.ToLower(parameters.Mode) == constants.CommunicationModeOutbound {

		service, err = newOutboundService(&parameters.Nats, parameters.RequestHandler)
		if err != nil {
			return nil, errors.Wrapf(err, "Error creating the HVS subscriber")
		}

		if service == nil {
			return nil, errors.Wrapf(err, "Error: could not initialize hvs subscriber")
		}

	} else if parameters.Mode == "" || strings.ToLower(parameters.Mode) == constants.CommunicationModeHttp {

		// create and start webservice
		service, err = newWebService(&parameters.Web, parameters.RequestHandler)
		if err != nil {
			return nil, errors.Wrapf(err, "Error while creating trustagent service")
		}

	} else {
		return nil, errors.Errorf("Unknown communication mode %s", parameters.Mode)
	}

	return service, nil
}
