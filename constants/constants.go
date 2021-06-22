/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "time"

const (
	InstallationDir            = "/opt/trustagent/"
	ConfigDir                  = InstallationDir + "configuration/"
	ConfigFilePath             = ConfigDir + "config.yml"
	BinDir                     = InstallationDir + "bin/"
	LogDir                     = "/var/log/trustagent/"
	HttpLogFile                = LogDir + "http.log"
	DefaultLogFilePath         = LogDir + "trustagent.log"
	SecurityLogFilePath        = LogDir + "trustagent-security.log"
	TLSCertFilePath            = ConfigDir + "tls-cert.pem"
	TLSKeyFilePath             = ConfigDir + "tls-key.pem"
	EndorsementCertificateFile = ConfigDir + "endorsement-certificate.pem"
	AikCert                    = ConfigDir + "aik.pem"
	PrivacyCA                  = ConfigDir + "privacy-ca.cer"
	NatsCredentials            = ConfigDir + "credentials/trust-agent.creds"
	VarDir                     = InstallationDir + "var/"
	RamfsDir                   = VarDir + "ramfs/"
	SystemInfoDir              = VarDir + "system-info/"
	PlatformInfoFilePath       = SystemInfoDir + "platform-info"
	MeasureLogFilePath         = VarDir + "measure-log.json"
	BindingKeyCertificatePath  = "/etc/workload-agent/bindingkey.pem"
	TBootXmMeasurePath         = "/opt/tbootxm/bin/measure"
	DevMemFilePath             = "/dev/mem"
	Tpm2FilePath               = "/sys/firmware/acpi/tables/TPM2"
	AppEventFilePath           = RamfsDir + "pcr_event_log"
	RootUserName               = "root"
	TagentUserName             = "tagent"
	DefaultPort                = 1443
	FlavorUUIDs                = "FLAVOR_UUIDS"
	DefaultLogEntryMaxlength   = 300
	FlavorLabels               = "FLAVOR_LABELS"
	ServiceName                = "tagent.service"
	ExplicitServiceName        = "Trust Agent"
	TAServiceName              = "TA"
	ServiceStatusCommand       = "systemctl status " + ServiceName
	ServiceStopCommand         = "systemctl stop " + ServiceName
	ServiceStartCommand        = "systemctl start " + ServiceName
	ServiceDisableCommand      = "systemctl disable " + ServiceName
	ServiceDisableInitCommand  = "systemctl disable tagent_init.service"
	UninstallTbootXmScript     = "/opt/tbootxm/bin/tboot-xm-uninstall.sh"
	TrustedJWTSigningCertsDir  = ConfigDir + "jwt/"
	TrustedCaCertsDir          = ConfigDir + "cacerts/"
	DefaultKeyAlgorithm        = "rsa"
	DefaultKeyAlgorithmLength  = 3072
	JWTCertsCacheTime          = "1m"
	DefaultTaTlsCn             = "Trust Agent TLS Certificate"
	DefaultTaTlsSan            = "127.0.0.1,localhost"
	TrustAgentEnvMaxLength     = 10000
	FlavorUUIDMaxLength        = 500
	FlavorLabelsMaxLength      = 500
	DefaultReadTimeout         = 30 * time.Second
	DefaultReadHeaderTimeout   = 10 * time.Second
	DefaultWriteTimeout        = 10 * time.Second
	DefaultIdleTimeout         = 10 * time.Second
	DefaultMaxHeaderBytes      = 1 << 20
	AikSecretKeyFile           = ConfigDir + "aiksecretkey"
	MaxHashLength              = 128
	TagIndexSize               = 2 + MaxHashLength // 2 bytes for length (short int) and enough bytes for future hash algorithms provided by HVS.
	CommunicationModeHttp      = "http"
	CommunicationModeOutbound  = "outbound"
)

// Env Variables
const (
	EnvTPMOwnerSecret            = "TPM_OWNER_SECRET"
	EnvMtwilsonAPIURL            = "HVS_URL"
	EnvTAPort                    = "TRUSTAGENT_PORT"
	EnvCMSBaseURL                = "CMS_BASE_URL"
	EnvCMSTLSCertDigest          = "CMS_TLS_CERT_SHA384"
	EnvAASBaseURL                = "AAS_API_URL"
	EnvTLSCertCommonName         = "TA_TLS_CERT_CN"
	EnvCertSanList               = "SAN_LIST"
	EnvCurrentIP                 = "CURRENT_IP"
	EnvBearerToken               = "BEARER_TOKEN"
	EnvLogEntryMaxlength         = "LOG_ENTRY_MAXLENGTH"
	EnvTALogLevel                = "TRUSTAGENT_LOG_LEVEL"
	EnvTALogEnableConsoleLog     = "TA_ENABLE_CONSOLE_LOG"
	EnvTAServerReadTimeout       = "TA_SERVER_READ_TIMEOUT"
	EnvTAServerReadHeaderTimeout = "TA_SERVER_READ_HEADER_TIMEOUT"
	EnvTAServerWriteTimeout      = "TA_SERVER_WRITE_TIMEOUT"
	EnvTAServerIdleTimeout       = "TA_SERVER_IDLE_TIMEOUT"
	EnvTAServerMaxHeaderBytes    = "TA_SERVER_MAX_HEADER_BYTES"
	EnvTAServiceMode             = "TA_SERVICE_MODE"
	EnvNATServers                = "NATS_SERVERS"
	EnvTAHostId                  = "TA_HOST_ID"
)

// "TODO" comment -- the SHA constants should live in intel-secl/pkg/model/
type SHAAlgorithm string

const (
	SHA1    SHAAlgorithm = "SHA1"
	SHA256  SHAAlgorithm = "SHA256"
	SHA384  SHAAlgorithm = "SHA384"
	SHA512  SHAAlgorithm = "SHA512"
	UNKNOWN SHAAlgorithm = "unknown"
)
