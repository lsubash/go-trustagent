/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"intel/isecl/go-trust-agent/v4/config"
	"intel/isecl/go-trust-agent/v4/constants"
	"intel/isecl/lib/common/v4/setup"
	"strconv"
	"time"
)

type UpdateServiceConfig struct {
	cfg **config.TrustAgentConfiguration
}

// Download's the privacy CA from HVS.
func (task *UpdateServiceConfig) Run(c setup.Context) error {
	log.Trace("tasks/update_service_config:Run() Entering")
	defer log.Trace("tasks/update_service_config:Run() Leaving")
	fmt.Println("Running setup task: update-service-config")

	//---------------------------------------------------------------------------------------------
	// TRUSTAGENT_PORT
	//---------------------------------------------------------------------------------------------
	port := 0
	port, err := c.GetenvInt(constants.EnvTAPort, "Trust Agent Listener Port")
	if port == 0 { // zero indicates the env was not present
		port = constants.DefaultPort
	}

	if (*task.cfg).WebService.Port != port {
		(*task.cfg).WebService.Port = port
	}

	//---------------------------------------------------------------------------------------------
	// LOG_ENTRY_MAXLENGTH
	//---------------------------------------------------------------------------------------------
	logEntryMaxLength, err := c.GetenvInt(constants.EnvLogEntryMaxlength, "Maximum length of each entry in a log")
	if err == nil && logEntryMaxLength >= 300 {
		(*task.cfg).Logging.LogEntryMaxLength = logEntryMaxLength
	} else {
		fmt.Println("Invalid Log Entry Max Length defined (should be >= ", constants.DefaultLogEntryMaxlength, "), using default value:", constants.DefaultLogEntryMaxlength)
		(*task.cfg).Logging.LogEntryMaxLength = constants.DefaultLogEntryMaxlength
	}

	//---------------------------------------------------------------------------------------------
	// TRUSTAGENT_LOG_LEVEL
	//---------------------------------------------------------------------------------------------
	ll, err := c.GetenvString(constants.EnvTALogLevel, "Logging Level")
	if err == nil {
		llp, err := logrus.ParseLevel(ll)
		if err == nil {
			(*task.cfg).Logging.LogLevel = llp.String()
			fmt.Printf("Log level set %s\n", ll)
		} else {
			fmt.Println("There was an error retrieving the log level from ", constants.EnvTALogLevel)
		}
	}

	if (*task.cfg).Logging.LogLevel == "" {
		fmt.Println(constants.EnvTALogLevel, " not defined, using default log level: Info")
		(*task.cfg).Logging.LogLevel = logrus.InfoLevel.String()
	}

	//---------------------------------------------------------------------------------------------
	// TA_ENABLE_CONSOLE_LOG
	//---------------------------------------------------------------------------------------------
	(*task.cfg).Logging.LogEnableStdout = false
	logEnableStdout, err := c.GetenvString(constants.EnvTALogEnableConsoleLog, "Trustagent Enable standard output")
	if err == nil && logEnableStdout != "" {
		(*task.cfg).Logging.LogEnableStdout, err = strconv.ParseBool(logEnableStdout)
		if err != nil {
			fmt.Println("Error while parsing the variable, ", constants.EnvTALogEnableConsoleLog, " setting to default value false")
		}
	}

	//---------------------------------------------------------------------------------------------
	// HTTP Server Settings
	//---------------------------------------------------------------------------------------------
	readTimeout, err := c.GetenvInt(constants.EnvTAServerReadTimeout, "Trustagent Read Timeout")
	if err != nil {
		log.Info("config/config:LoadEnvironmentVariables() could not parse the variable ", constants.EnvTAServerReadTimeout, "setting default value 30s")
		(*task.cfg).WebService.ReadTimeout = constants.DefaultReadTimeout
	} else {
		(*task.cfg).WebService.ReadTimeout = time.Duration(readTimeout) * time.Second
	}

	readHeaderTimeout, err := c.GetenvInt(constants.EnvTAServerReadHeaderTimeout, "Trustagent Read Header Timeout")
	if err != nil {
		log.Info("config/config:LoadEnvironmentVariables() could not parse the variable ", constants.EnvTAServerReadHeaderTimeout, ", setting default value 10s")
		(*task.cfg).WebService.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
	} else {
		(*task.cfg).WebService.ReadHeaderTimeout = time.Duration(readHeaderTimeout) * time.Second
	}

	writeTimeout, err := c.GetenvInt(constants.EnvTAServerWriteTimeout, "Trustagent Write Timeout")
	if err != nil {
		log.Info("config/config:LoadEnvironmentVariables() could not parse the variable ", constants.EnvTAServerWriteTimeout, "setting default value 10s")
		(*task.cfg).WebService.WriteTimeout = constants.DefaultWriteTimeout
	} else {
		(*task.cfg).WebService.WriteTimeout = time.Duration(writeTimeout) * time.Second
	}

	idleTimeout, err := c.GetenvInt(constants.EnvTAServerIdleTimeout, "Trustagent Idle Timeout")
	if err != nil {
		log.Info("config/config:LoadEnvironmentVariables() could not parse the variable ", constants.EnvTAServerIdleTimeout, ", setting default value 10s")
		(*task.cfg).WebService.IdleTimeout = constants.DefaultIdleTimeout
	} else {
		(*task.cfg).WebService.IdleTimeout = time.Duration(idleTimeout) * time.Second
	}

	maxHeaderBytes, err := c.GetenvInt(constants.EnvTAServerMaxHeaderBytes, "Trustagent Max Header Bytes Timeout")
	if err != nil {
		log.Info("config/config:LoadEnvironmentVariables() could not parse the variable ", constants.EnvTAServerMaxHeaderBytes, ", setting default value 10s")
		(*task.cfg).WebService.MaxHeaderBytes = constants.DefaultMaxHeaderBytes
	} else {
		(*task.cfg).WebService.MaxHeaderBytes = maxHeaderBytes
	}

	//---------------------------------------------------------------------------------------------
	// Save config
	//---------------------------------------------------------------------------------------------

	err = (*task.cfg).Save()
	if err != nil {
		return errors.Wrap(err, "Error saving configuration")
	}

	return nil
}

func (task *UpdateServiceConfig) Validate(c setup.Context) error {
	log.Trace("tasks/update_service_config:Validate() Entering")
	defer log.Trace("tasks/update_service_config:Validate() Leaving")

	if (*task.cfg).WebService.Port == 0 || (*task.cfg).WebService.Port > 65535 {
		return errors.Errorf("The Trust-Agent service requires that the configuration contains a valid port number: '%d'", (*task.cfg).WebService.Port)
	}

	log.Info("tasks/update_service_config:Validate() update_service_config task was successful")
	return nil
}
