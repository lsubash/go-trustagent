// +build linux

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"common/log/message"
	"common/validation"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	commLog "intel/isecl/lib/common/log"
	"intel/isecl/go-trust-agent/config"
	"intel/isecl/go-trust-agent/constants"
	"intel/isecl/go-trust-agent/resource"
	"intel/isecl/go-trust-agent/tasks"
	"intel/isecl/go-trust-agent/util"
	"intel/isecl/go-trust-agent/vsclient"
	commonExec "intel/isecl/lib/common/exec"
	"intel/isecl/lib/platform-info/platforminfo"
	"intel/isecl/lib/tpmprovider"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("")
	fmt.Println("    tagent <command> [arguments]")
	fmt.Println("")
	fmt.Println("Available Commands:")
	fmt.Println("    help|-h|-help    Show this help message")
	fmt.Println("    setup [task]     Run setup task")
	fmt.Println("    uninstall        Uninstall tagent")
	fmt.Println("    version          Show the version of trustagent")
	fmt.Println("    start*           Used by systemd to start the trustagent")
	fmt.Println("")
	fmt.Println("    * Please use 'systemctl' to manage the trustagent service")
	fmt.Println("")
	fmt.Println("Available Tasks for setup:")
	fmt.Println("    tagent setup all (or with empty 3rd argument)")
	fmt.Println("        - Runs all setup tasks to provision the trustagent.")
	fmt.Println("    tagent setup download-ca-cert [--force]")
	fmt.Println("        - Fetches the latest CMS Root CA Certificates. --force option overwrites existing root CA certificates.")
	fmt.Println("    tagent setup download-cert [--force]")
	fmt.Println("        - Fetches a signed TLS Certificate from CMS. --force option overwrites existing TLS certificates.")
	fmt.Println("    tagent setup create-host")
	fmt.Println("        - Registers the trustagent with the verification service.")
	fmt.Println("    tagent setup create-host-unique-flavor")
	fmt.Println("        - Populates the verification service with the host unique flavor")
	fmt.Println("    tagent setup get-configured-manifest")
	fmt.Println("        - Uses environment variables to pull application-integrity")
	fmt.Println("          manifests from the verification service.")
	fmt.Println("    tagent setup replace-tls-keypair")
	fmt.Println("        - Recreates the trustagent's tls key/pair.")
	fmt.Println("")
}

func updatePlatformInfo() error {
	log.Trace("main:updatePlatformInfo() Entering")
	defer log.Trace("main:updatePlatformInfo() Leaving")
	// make sure the system-info directory exists
	_, err := os.Stat(constants.SystemInfoDir)
	if err != nil {
		return errors.Wrapf(err, "main:updatePlatformInfo() Error while checking the existence of %s", constants.SystemInfoDir)
	}

	// create the 'platform-info' file
	f, err := os.Create(constants.PlatformInfoFilePath)
	defer f.Close()
	if err != nil {
		return errors.Wrapf(err, "main:updatePlatformInfo() Error while creating %s", constants.PlatformInfoFilePath)
	}

	// collect the platform info
	secLog.Info("%s main:updatePlatformInfo() Trying to fetch platform info", message.SU)
	platformInfo, err := platforminfo.GetPlatformInfo()
	if err != nil {
		return errors.Wrap(err, "main:updatePlatformInfo() Error while fetching platform info")
	}

	// serialize to json
	b, err := json.Marshal(platformInfo)
	if err != nil {
		return errors.Wrap(err, "main:updatePlatformInfo() Error while serializing platform info")
	}

	_, err = f.Write(b)
	if err != nil {
		return errors.Wrapf(err, "main:updatePlatformInfo() Error while writing into File: %s", constants.PlatformInfoFilePath)
	}

	log.Info("main:updatePlatformInfo() Successfully updated platform-info")
	return nil
}

func updateMeasureLog() error {
	log.Trace("main:updateMeasureLog() Entering")
	defer log.Trace("main:updateMeasureLog() Leaving")

	secLog.Info("%s main:updateMeasureLog() Running %s using system administrative privilages", message.SU, constants.ModuleAnalysis)
	cmd := exec.Command(constants.ModuleAnalysis)
	cmd.Dir = constants.BinDir
	results, err := cmd.Output()
	if err != nil {
		return errors.Errof("main:updateMeasureLog() module_analysis_sh error: %s", results)
	}

	log.Info("main:updateMeasureLog() Successfully updated measureLog.xml")
	return nil
}

func printVersion() {

	if len(os.Args) > 2 && os.Args[2] == "short" {
		major, err := util.GetMajorVersion()
		if err != nil {
			fmt.Fprintln(os.Stderr,"Error while fetching Major version: %+v", err)
			os.Exit(1)
		}

		minor, err := util.GetMinorVersion()
		if err != nil {
			fmt.Fprintln(os.Stderr,"Error while fetching Minor version: %+v", err)
			os.Exit(1)
		}

		fmt.Printf("%d.%d\n", major, minor)
	} else {
		fmt.Printf("tagent %s-%s [%s]\n", util.Version, util.GitHash, util.CommitDate)
	}
}

func uninstall() error {

	// stop/disable tagent service (if installed and running)
	//
	// systemctl status tagent will...
	// return 4 if not present on the system
	// return 3 if stopped
	// return 0 if running
	//
	// If not present, do nothing
	// if stopped, remove
	// if running, stop and remove
	_, _, err := commonExec.RunCommandWithTimeout(constants.ServiceStatusCommand, 5)
	if err == nil {
		// installed and running, stop and disable
		_, _, _ = commonExec.RunCommandWithTimeout(constants.ServiceStopCommand, 5)
		_, _, _ = commonExec.RunCommandWithTimeout(constants.ServiceDisableCommand, 5)
	} else {
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			if waitStatus.ExitStatus() == 3 {
				// stopped, just disable
				_, _, _ = commonExec.RunCommandWithTimeout(constants.ServiceDisableCommand, 5)
			} else if waitStatus.ExitStatus() == 4 {
				// do nothing if not installed
			} else {
				return errors.Errorf("main:uninstall() Service status returned unhandled error code %d", waitStatus.ExitStatus())
			}
		} else {
			return errors.Errorf("main:uninstall() An unhandled error occurred with the tagent service: %s", err)
		}
	}

	log.Info("main:uninstall() TrustAgent service removed successfully")

	//
	// uninstall tbootxml (if uninstall script is present)
	//
	if _, err := os.Stat(constants.UninstallTbootXmScript); err == nil {
		_, _, err = commonExec.RunCommandWithTimeout(constants.UninstallTbootXmScript, 15)
		if err != nil {
			return errors.Errorf("main:uninstall() An error occurred while uninstalling tboot: %s", err)
		}
	}

	log.Info("main:uninstall() tbootxm removed successfully")

	//
	// remove all of tagent files (in /opt/trustagent/)
	//
	if _, err := os.Stat(constants.InstallationDir); err == nil {
		err = os.RemoveAll(constants.InstallationDir)
		if err != nil {
			log.Errorf("main:uninstall() An error occurred removing the trustagent files: %s", err)
		}
	}

	log.Info("main:uninstall() trustagent files removed successfully")

	return nil
}

func newVSClientConfig(cfg *config.TrustAgentConfiguration) (*vsclient.VSClientConfig, error) {

	jwtToken := os.Getenv(constants.BearerTokenEnv)
	if jwtToken == "" {
		fmt.Fprintln(os.Stderr, "BEARER_TOKEN is not defined in environment")
		return nil, errors.New("BEARER_TOKEN is not defined in environment")
	}

	vsClientConfig := vsclient.VSClientConfig{
		BaseURL: cfg.HVS.Url,
		BearerToken: jwtToken,
	}

	return &vsClientConfig, nil
}

func main() {

	if len(os.Args) <= 1 {
		fmt.Fprintln(os.Stderr, "Invalid arguments: %s\n", os.Args)
		printUsage()
		os.Exit(1)
	}

	if err := validation.ValidateStrings(os.Args); err != nil {
		secLog.WithError(err).Error("%s main:main() Invalid arguments", message.InvalidInputBadParam)
		fmt.Fprintln(os.Stderr, "Invalid arguments")
		printUsage()
		os.Exit(1)
	}

	cfg, err := config.NewConfigFromYaml(constants.ConfigFilePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "main:main() Error while parsing configuration file: %+v", err)
		os.Exit(1)
	}

	currentUser, _ := user.Current()

	cmd := os.Args[1]
	switch cmd {
	case "version":
		printVersion()
	case "start":

		//
		// The legacy trust agent was a shell script that did work like creating platform-info,
		// measureLog.xml, etc.  The systemd service ran that script as root.  Now, systemd is
		// starting tagent (go exec) which shells out to module_anlaysis.sh to create measureLog.xml
		// (requires root permissions).  So, 'tagent start' is two steps...
		// 1.) There tagent.service runs as root and calls 'start'.  platform-info and measureLog.xml
		// are created under that account.
		// 2.) 'start' option then forks the service running as 'tagent' user.
		//
		if currentUser.Username != constants.RootUserName {
			fmt.Printf("'tagent start' must be run as root, not  user '%s'\n", currentUser.Username)
			os.Exit(1)
		}

		err = LogConfiguration(true, cfg.LogEnableStdout)
		if err != nil {
			fmt.Fprintln(os.Stderr, "main:main() Error while setting log configuration %+v", err)
			os.Exit(1)
		}

		err = updatePlatformInfo()
		if err != nil {
			log.Errorf("main:main() Error while creating platform-info: %s\n", err.Error())
		}

		err = updateMeasureLog()
		if err != nil {
			log.Errorf("main:main() Error While creating measureLog.xml: %s\n", err.Error())
		}

		tagentUser, err := user.Lookup(constants.TagentUserName)
		if err != nil {
			log.Errorf("main:main() Could not find user '%s'", constants.TagentUserName)
			os.Exit(1)
		}

		uid, err := strconv.ParseUint(tagentUser.Uid, 10, 32)
		if err != nil {
			log.Errorf("main:main() Could not parse tagent user uid '%s'", tagentUser.Uid)
			os.Exit(1)
		}

		gid, err := strconv.ParseUint(tagentUser.Gid, 10, 32)
		if err != nil {
			log.Errorf("main:main() Could not parse tagent user gid '%s'", tagentUser.Gid)
			os.Exit(1)
		}

		// take ownership of all of the files in /opt/trusagent before forking the
		// tagent service
		_ = filepath.Walk(constants.InstallationDir, func(fileName string, info os.FileInfo, err error) error {
			//log.Infof("Owning file %s", fileName)
			err = os.Chown(fileName, int(uid), int(gid))
			if err != nil {
				log.Errorf("main:main() Could not own file '%s'", fileName)
				return err
			}

			return nil
		})

		// spawn 'tagent startService' as the 'tagent' user
		cmd := exec.Command(constants.TagentExe, "startService")
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.Dir = constants.BinDir
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}

		err = cmd.Start()
		if err != nil {
			log.Errorf("main:main() error while starting the command %s : %s", constants.TagentExe, err)
			os.Exit(1)
		}

	case "startService":
		if currentUser.Username != constants.TagentUserName {
			fmt.Printf("'tagent startService' must be run as the agent user, not  user '%s'\n", currentUser.Username)
			os.Exit(1)
		}

		err = LogConfiguration(true, cfg.LogEnableStdout)
		if err != nil {
			log.Errorf("main:main() Error while setting log configuration %+v", err)
			os.Exit(1)
		}

		// make sure the config is valid before starting the trust agent service
		err = cfg.Validate()
		if err != nil {
			log.Errorf("main:main() Error while validating the configuration file: %s", err)
			os.Exit(1)
		}

		tpmFactory, err := tpmprovider.NewTpmFactory()
		if err != nil {
			log.Errorf("main:main() Could not create the tpm factory %+v", err)
			os.Exit(1)
		}

		// create and start webservice
		service, err := resource.CreateTrustAgentService(cfg, tpmFactory)
		if err != nil {
			log.Errorf("main:main() Error while creating trustagent service %+v", err)
			os.Exit(1)
		}

		service.Start()
	case "setup":

		err = LogConfiguration(true, cfg.LogEnableStdout)
		// only apply env vars to config before starting 'setup' tasks
		cfg.LoadEnvironmentVariables()

		if currentUser.Username != constants.RootUserName {
			log.Errorf("main:main() 'tagent setup' must be run as root, not  user '%s'\n", currentUser.Username)
			os.Exit(1)
		}

		var setupCommand string
		if len(os.Args) > 2 {
			setupCommand = os.Args[2]
		} else {
			setupCommand = tasks.DefaultSetupCommand
		}

		vsClientConfig, err := newVSClientConfig(cfg)
		if err != nil {
			log.Errorf("main:main() Could not create the vsclient config: %s", err)
			os.Exit(1)
		}

		vsClientFactory, err := vsclient.NewVSClientFactory(vsClientConfig)
		if err != nil {
			log.Errorf("main:main() Could not create the vsclient factory: %s", err)
			os.Exit(1)
		}

		tpmFactory, err := tpmprovider.NewTpmFactory()
		if err != nil {
			log.Errorf("main:main() Could not create the tpm factory: %s", err)
			os.Exit(1)
		}

		registry, err := tasks.CreateTaskRegistry(vsClientFactory, tpmFactory, cfg, os.Args)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error while creating task registry %+v", err)
			os.Exit(1)
		}

		err = registry.RunCommand(setupCommand)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error while running setup Command %s, %+v", setupCommand, err)
			os.Exit(1)
		}

	case "config":
		if len(os.Args) != 3 {
			fmt.Printf("'config' requires an additional parameter.\n")
		}

		cfg.PrintConfigSetting(os.Args[2])

	case "uninstall":
		err = uninstall()
		if err != nil {
			fmt.Fprintf(os.Stderr, "main:main() Error while running uninstalling trustagent %+v\n", err)
			os.Exit(1)
		}

	case "help":
		fallthrough
	case "-help":
		fallthrough
	case "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Invalid option: '%s'\n\n", cmd)
		printUsage()
	}
}
