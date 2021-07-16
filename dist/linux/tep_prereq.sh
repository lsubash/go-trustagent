#!/bin/bash
#--------------------------------------------------------------------------------------------------
# T R U S T A G E N T   I N S T A L L E R
#
# Overall process:
# 1. Make sure the script is ready to be run (root user, dependencies installed, etc.).
# 2. Load trustagent.env if present and apply exports.
# 3. Create tagent user
# 4. Create directories, copy files and own them by tagent user.
# 5. Install application-agent
# 6. Make sure tpm2-abrmd is started and deploy tagent service.
# 7. If 'automatic provisioning' is enabled (PROVISION_ATTESTATION=y), initiate 'tagent setup'.
#    Otherwise, exit with a message that the user must provision the trust agent and start the
#    service.
#--------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
# Script variables
#--------------------------------------------------------------------------------------------------
DEFAULT_TRUSTAGENT_HOME=/home/root/tep_luks_dev/trustagent
DEFAULT_TRUSTAGENT_INBUILT=/usr/bin/trustagent
DEFAULT_TRUSTAGENT_USERNAME=root

export PROVISION_ATTESTATION=${PROVISION_ATTESTATION:-n}
export TRUSTAGENT_HOME=${TRUSTAGENT_HOME:-$DEFAULT_TRUSTAGENT_HOME}

TRUSTAGENT_EXE=tagent
TRUSTAGENT_ENV_FILE=trustagent.env
TRUSTAGENT_SERVICE=tagent.service
TRUSTAGENT_INIT_SERVICE=tagent_init.service
TRUSTAGENT_BIN_DIR=$DEFAULT_TRUSTAGENT_INBUILT
TRUSTAGENT_LOG_DIR=${TRUSTAGENT_LOG_DIR:-/home/root/tep_luks_dev/log/trustagent}
TRUSTAGENT_CFG_DIR=$TRUSTAGENT_HOME/configuration
TRUSTAGENT_VAR_DIR=$TRUSTAGENT_HOME/var/
TPM2_ABRMD_SERVICE=tpm2-abrmd.service

#--------------------------------------------------------------------------------------------------
# 1. Script prerequisites
#--------------------------------------------------------------------------------------------------
echo "Starting trustagent installation from " $USER_PWD

if [[ $EUID -ne 0 ]]; then
    echo_failure "This installer must be run as root"
    exit 1
fi

# make sure tagent.service is not running or install won't work
systemctl status $TRUSTAGENT_SERVICE 2>&1 >/dev/null
if [ $? -eq 0 ]; then
    echo_failure "Please stop the tagent service before running the installer"
    exit 1
fi

is_measured_launch() {
  local mle=$(txt-stat | grep 'TXT measured launch: TRUE')
  if [ -n "$mle" ]; then
    return 0
  else
    return 1
  fi
}

is_uefi_boot() {
  if [ -d /sys/firmware/efi ]; then
    return 0
  else
    return 1
  fi
}

is_tpm_driver_loaded() {

  if [ ! -e /dev/tpm0 ]; then
     return 1
  fi
  return 0
}

is_reboot_required() {
  local should_reboot=no

  if ! is_tpm_driver_loaded; then
    echo_warning "TPM driver is not loaded, reboot required"
    should_reboot=yes
  else
    echo "TPM driver is already loaded"
  fi
  
  if [ "$should_reboot" == "yes" ]; then
    return 0
  else
    return 1
  fi
}

is_reboot_required
rebootRequired=$?

# make sure tpm2-abrmd service is installed
systemctl list-unit-files --no-pager | grep $TPM2_ABRMD_SERVICE >/dev/null
if [ $? -ne 0 ]; then
    echo_failure "The tpm2-abrmd service must be installed"
    exit 1
fi

export LOG_ROTATION_PERIOD=${LOG_ROTATION_PERIOD:-weekly}
export LOG_COMPRESS=${LOG_COMPRESS:-compress}
export LOG_DELAYCOMPRESS=${LOG_DELAYCOMPRESS:-delaycompress}
export LOG_COPYTRUNCATE=${LOG_COPYTRUNCATE:-copytruncate}
export LOG_SIZE=${LOG_SIZE:-100M}
export LOG_OLD=${LOG_OLD:-12}

mkdir -p /etc/logrotate.d

if [ ! -a /etc/logrotate.d/trustagent ]; then
  echo "/var/log/trustagent/*.log {
    missingok
    notifempty
    rotate $LOG_OLD
    maxsize $LOG_SIZE
    nodateext
    $LOG_ROTATION_PERIOD
    $LOG_COMPRESS
    $LOG_DELAYCOMPRESS
    $LOG_COPYTRUNCATE
}" >/etc/logrotate.d/trustagent
fi

#--------------------------------------------------------------------------------------------------
# 2. Load environment variable file
#--------------------------------------------------------------------------------------------------
if [ -f $USER_PWD/$TRUSTAGENT_ENV_FILE ]; then
    env_file=$USER_PWD/$TRUSTAGENT_ENV_FILE
elif [ -f ~/$TRUSTAGENT_ENV_FILE ]; then
    env_file=~/$TRUSTAGENT_ENV_FILE
fi

if [ -z "$env_file" ]; then
    echo "The trustagent.env file was not provided, 'automatic provisioning' will not be performed"
    PROVISION_ATTESTATION="false"
else
    echo "Using environment file $env_file"
    source $env_file
    env_file_exports=$(cat $env_file | grep -E '^[A-Z0-9_]+\s*=' | cut -d = -f 1)
    if [ -n "$env_file_exports" ]; then eval export $env_file_exports; fi
fi

#--------------------------------------------------------------------------------------------------
# 3. Create tagent user
#--------------------------------------------------------------------------------------------------
# Tagent user is created in TEP yocto build

#--------------------------------------------------------------------------------------------------
# 4. Setup directories, copy files and own them
#--------------------------------------------------------------------------------------------------
mkdir -p $TRUSTAGENT_HOME
mkdir -p $TRUSTAGENT_CFG_DIR
mkdir -p $TRUSTAGENT_LOG_DIR
mkdir -p $TRUSTAGENT_VAR_DIR
mkdir -p $TRUSTAGENT_VAR_DIR/system-info
mkdir -p $TRUSTAGENT_VAR_DIR/ramfs
mkdir -p $TRUSTAGENT_CFG_DIR/cacerts
mkdir -p $TRUSTAGENT_CFG_DIR/jwt
mkdir -p $TRUSTAGENT_CFG_DIR/credentials

# copy default and workload software manifest to /opt/trustagent/var/ (application-agent)
if ! stat $TRUSTAGENT_VAR_DIR/manifest_* 1>/dev/null 2>&1; then
    TA_VERSION=$(tagent version short)
    UUID=$(uuidgen)
    cp manifest_tpm20.xml $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml
    sed -i "s/Uuid=\"\"/Uuid=\"${UUID}\"/g" $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml
    sed -i "s/Label=\"ISecL_Default_Application_Flavor_v\"/Label=\"ISecL_Default_Application_Flavor_v${TA_VERSION}_TPM2.0\"/g" $TRUSTAGENT_VAR_DIR/manifest_"$UUID".xml
fi


# make sure /tmp is writable -- this is needed when the 'trustagent/v2/application-measurement' endpoint
# calls /opt/tbootxm/bin/measure.
# TODO:  Resolve this in lib-workload-measure (hard coded path)
chmod 1777 /tmp

# TODO:  remove the dependency that tpmextend has on the tpm version in /opt/trustagent/configuration/tpm-version
if [ -f "$TRUSTAGENT_CFG_DIR/tpm-version" ]; then
    rm -f $TRUSTAGENT_CFG_DIR/tpm-version
fi
echo "2.0" >$TRUSTAGENT_CFG_DIR/tpm-version

#--------------------------------------------------------------------------------------------------
# 5. Install application-agent
#--------------------------------------------------------------------------------------------------

## Not required for TEP

#--------------------------------------------------------------------------------------------------
# 6. Enable/configure services, etc.
#--------------------------------------------------------------------------------------------------
# make sure the tss user owns /dev/tpm0 or tpm2-abrmd service won't start (this file does not
# exist when using the tpm simulator, so check for its existence)
if [ -c /dev/tpm0 ]; then
    chown tss:tss /dev/tpm0
fi
if [ -c /dev/tpmrm0 ]; then
    chown tss:tss /dev/tpmrm0
fi

# Enable tagent service and tagent 'init' service
systemctl disable $TRUSTAGENT_INIT_SERVICE >/dev/null 2>&1
systemctl enable  $TRUSTAGENT_INIT_SERVICE
systemctl disable $TRUSTAGENT_SERVICE >/dev/null 2>&1
systemctl enable  $TRUSTAGENT_SERVICE
systemctl daemon-reload

#--------------------------------------------------------------------------------------------------
# 7. If automatic provisioning is enabled, do it here...
#--------------------------------------------------------------------------------------------------
if [[ "$PROVISION_ATTESTATION" == "y" || "$PROVISION_ATTESTATION" == "Y" || "$PROVISION_ATTESTATION" == "yes" ]]; then
    echo "Automatic provisioning is enabled, using HVS url $HVS_URL"

    # make sure that tpm2-abrmd is running before running 'tagent setup'
    systemctl status $TPM2_ABRMD_SERVICE 2>&1 >/dev/null
    if [ $? -ne 0 ]; then
        echo "Starting $TPM2_ABRMD_SERVICE"
        systemctl start $TPM2_ABRMD_SERVICE 2>&1 >/dev/null
        sleep 3

        # TODO:  in production we want to check that is is running, but in development
        # the simulator needs to be started first -- for now warn, don't error...
        systemctl status $TPM2_ABRMD_SERVICE 2>&1 >/dev/null
        if [ $? -ne 0 ]; then
            echo_warning "WARNING: Could not start $TPM2_ABRMD_SERVICE"
        fi
    fi

    $TRUSTAGENT_EXE setup
    setup_results=$?

    if [ $setup_results -eq 0 ]; then

        systemctl start $TRUSTAGENT_SERVICE
        echo "Waiting for $TRUSTAGENT_SERVICE to start"
        sleep 5

        systemctl status $TRUSTAGENT_SERVICE 2>&1 >/dev/null
        if [ $? -ne 0 ]; then
            echo_failure "Installation completed with errors - $TRUSTAGENT_SERVICE did not start."
            echo_failure "Please check errors in syslog using \`journalctl -u $TRUSTAGENT_SERVICE\`"
            exit 1
        fi

        echo "$TRUSTAGENT_SERVICE is running"

        if [[ "$AUTOMATIC_REGISTRATION" == "y" || "$AUTOMATIC_REGISTRATION" == "Y" || "$AUTOMATIC_REGISTRATION" == "yes" ]]; then
            echo "Automatically registering host with HVS..."
            tagent setup create-host
            tagent setup create-host-unique-flavor
        fi

        if [[ "$AUTOMATIC_PULL_MANIFEST" == "y" || "$AUTOMATIC_PULL_MANIFEST" == "Y" || "$AUTOMATIC_PULL_MANIFEST" == "yes" ]]; then
            echo "Automatically pulling application-manifests from HVS..."
            tagent setup get-configured-manifest
        fi
    else
        echo_failure "'$TRUSTAGENT_EXE setup' failed"
        exit 1
    fi
else
    echo ""
    echo "Automatic provisioning is disabled. You must use 'tagent setup trustagent.env' command to complete (see tagent --help)"
    echo "The tagent service must also be started using command 'tagent start'"
fi

echo_success "Installation succeeded"
