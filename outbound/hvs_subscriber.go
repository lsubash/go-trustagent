package outbound

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/go-trust-agent/v4/common"
	"intel/isecl/go-trust-agent/v4/config"
	"intel/isecl/go-trust-agent/v4/constants"
	"intel/isecl/go-trust-agent/v4/util"
	"strings"
	"time"

	commLog "github.com/intel-secl/intel-secl/v4/pkg/lib/common/log"
	cos "github.com/intel-secl/intel-secl/v4/pkg/lib/common/os"
	taModel "github.com/intel-secl/intel-secl/v4/pkg/model/ta"

	"github.com/nats-io/nats.go"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type HVSSubscriber interface {
	Start() error
	Stop() error
}

func NewHVSSubscriber(handler common.RequestHandler, cfg *config.TrustAgentConfiguration) (HVSSubscriber, error) {

	if cfg.Nats.HostID == "" {
		return nil, errors.New("The configuration does not have a 'nats-host-id'.")
	}

	return &hvsSubscriberImpl{
		cfg:        cfg,
		handler:    handler,
		natsHostID: cfg.Nats.HostID,
	}, nil

}

type hvsSubscriberImpl struct {
	natsConnection *nats.EncodedConn
	handler        common.RequestHandler
	cfg            *config.TrustAgentConfiguration
	natsHostID     string
}

func (subscriber *hvsSubscriberImpl) Start() error {

	log.Infof("Starting outbound communications with nats-host-id '%s'", subscriber.natsHostID)

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	certs, err := cos.GetDirFileContents(constants.TrustedCaCertsDir, "*.pem")
	if err != nil {
		log.WithError(err).Errorf("Failed to append %q to RootCAs", constants.TrustedCaCertsDir)
	}

	for _, rootCACert := range certs {
		if ok := rootCAs.AppendCertsFromPEM(rootCACert); !ok {
			log.Debug("No certs appended, using system certs only")
		}
	}

	tlsConfig := tls.Config{
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
	}

	conn, err := nats.Connect(strings.Join(subscriber.cfg.Nats.Servers, ","),
		nats.Secure(&tlsConfig),
		nats.UserCredentials(constants.NatsCredentials),
		nats.ErrorHandler(func(nc *nats.Conn, s *nats.Subscription, err error) {
			if s != nil {
				log.Errorf("ERROR: NATS: Could not process subscription for subject %q: %v", s.Subject, err)
			} else {
				log.Errorf("ERROR: NATS: %v", err)
			}
		}))

	if err != nil {
		return errors.Wrapf(err, "Failed to connect to url %q", subscriber.cfg.Nats.Servers)
	}

	subscriber.natsConnection, err = nats.NewEncodedConn(conn, "json")
	if err != nil {
		log.WithError(err).Error("Error while wrapping an existing NATS connection to utilize the encoded connection")
	}

	log.Infof("Successfully connected to %q", subscriber.cfg.Nats.Servers)

	defer subscriber.natsConnection.Close()

	// subscribe to quote-request messages
	quoteSubject := taModel.CreateSubject(subscriber.natsHostID, taModel.NatsQuoteRequest)
	subscriber.natsConnection.Subscribe(quoteSubject, func(subject string, reply string, quoteRequest *taModel.TpmQuoteRequest) {
		quoteResponse, err := subscriber.handler.GetTpmQuote(quoteRequest)
		if err != nil {
			log.WithError(err).Error("Failed to handle quote-request")
		}

		subscriber.natsConnection.Publish(reply, quoteResponse)
	})

	//subscribe to host-info request messages
	hostInfoSubject := taModel.CreateSubject(subscriber.natsHostID, taModel.NatsHostInfoRequest)
	subscriber.natsConnection.Subscribe(hostInfoSubject, func(m *nats.Msg) {
		hostInfo, err := subscriber.handler.GetHostInfo()
		if err != nil {
			log.WithError(err).Error("Failed to handle quote-request")
		}

		subscriber.natsConnection.Publish(m.Reply, hostInfo)
	})

	// subscribe to aik request messages
	aikSubject := taModel.CreateSubject(subscriber.natsHostID, taModel.NatsAikRequest)
	subscriber.natsConnection.Subscribe(aikSubject, func(m *nats.Msg) {
		aik, err := subscriber.handler.GetAikDerBytes()
		if err != nil {
			log.WithError(err).Error("Failed to handle aik-request")
		}

		subscriber.natsConnection.Publish(m.Reply, aik)
	})

	// subscribe to deploy asset tag request messages
	deployTagSubject := taModel.CreateSubject(subscriber.natsHostID, taModel.NatsDeployAssetTagRequest)
	subscriber.natsConnection.Subscribe(deployTagSubject, func(subject string, reply string, tagWriteRequest *taModel.TagWriteRequest) {
		err := subscriber.handler.DeployAssetTag(tagWriteRequest)
		if err != nil {
			log.WithError(err).Error("Failed to handle deploy-asset-tag")
		}

		subscriber.natsConnection.Publish(reply, "")
	})

	// subscribe to binding key request messages
	bkSubject := taModel.CreateSubject(subscriber.natsHostID, taModel.NatsBkRequest)
	subscriber.natsConnection.Subscribe(bkSubject, func(m *nats.Msg) {
		bk, err := subscriber.handler.GetBindingCertificateDerBytes()
		if err != nil {
			log.WithError(err).Error("Failed to handle get-binding-certificate")
		}

		subscriber.natsConnection.Publish(m.Reply, bk)
	})

	// subscribe to deploy manifest request messages
	deployManifestSubject := taModel.CreateSubject(subscriber.natsHostID, taModel.NatsDeployManifestRequest)
	subscriber.natsConnection.Subscribe(deployManifestSubject, func(subject string, reply string, manifest *taModel.Manifest) {
		err = subscriber.handler.DeploySoftwareManifest(manifest)
		if err != nil {
			log.WithError(err).Error("Failed to handle deploy-manifest")
		}

		subscriber.natsConnection.Publish(reply, "")
	})

	// subscribe to application measurement request messages
	applicationMeasurementSubject := taModel.CreateSubject(subscriber.natsHostID, taModel.NatsApplicationMeasurementRequest)
	subscriber.natsConnection.Subscribe(applicationMeasurementSubject, func(subject string, reply string, manifest *taModel.Manifest) {
		measurement, err := subscriber.handler.GetApplicationMeasurement(manifest)
		if err != nil {
			log.WithError(err).Error("Failed to handle application-measurement-request")
		}

		subscriber.natsConnection.Publish(reply, measurement)
	})

	// subscribe to version requests
	versionSubject := taModel.CreateSubject(subscriber.natsHostID, taModel.NatsVersionRequest)
	subscriber.natsConnection.Subscribe(versionSubject, func(m *nats.Msg) {
		versionInfo, err := util.GetVersionInfo()
		if err != nil {
			log.WithError(err).Error("Failed to handle version-request")
		}

		subscriber.natsConnection.Publish(m.Reply, versionInfo)
	})

	log.Infof("Running Trust-Agent %s...", subscriber.natsHostID)
	// KWT:  This needs to block but not log repetive messages...
	for {
		time.Sleep(10 * time.Second)
	}

	return nil
}

func (subscriber *hvsSubscriberImpl) Stop() error {
	return fmt.Errorf("Not Implemented")
}
