#!/bin/bash

COMPONENT_NAME=trustagent
SERVICE_NAME=tagent
BIN_DIR=/opt/$COMPONENT_NAME/bin
VAR_DIR=/opt/$COMPONENT_NAME/var
CONFIG_DIR=/opt/$COMPONENT_NAME/configuration
CREDS_DIR=$CONFIG_DIR/credentials
echo "Starting $COMPONENT_NAME config upgrade to v4.0.0"
TPM_OWNER_SECRET=${TPM_OWNER_SECRET:-""}

if [ -f "/.container-env" ]; then
  source /etc/secret-volume/secrets.txt
  export BEARER_TOKEN
  export TPM_OWNER_SECRET
  ln -sfT /usr/bin/$SERVICE_NAME /$SERVICE_NAME
fi
if [[ -z $BEARER_TOKEN ]]; then
  echo "BEARER_TOKEN is required for the upgrade to v4.0.0"
  exit 1
fi

# If the user has not specified the TPM_OWNER_SECRET and the 'old secret'
# can be extracted from the old config file (ex. from v3.x), put that
# value in the environment so that 'tagent setup' picks it up and can
# provision of the TPM.
if [ "$TPM_OWNER_SECRET" == "" ]; then
  OLD_SECRET=`grep 'ownersecretkey:' $CONFIG_DIR/config.yml | awk '{print $2}'`
  if [ ${OLD_SECRET} ]; then
    echo "Using TPM_OWNER_SECRET from previous configuration"
    export TPM_OWNER_SECRET=$OLD_SECRET
  else
    echo "The existing TPM_OWNER_SECRET could not be found in the previous configuration"
  fi
fi

if [[ -z $TPM_OWNER_SECRET ]]; then
  echo "TPM_OWNER_SECRET is required for the upgrade to v4.0.0"
  exit 1
fi

echo "Cleaning up module analysis script"
rm -rf $BIN_DIR/module*
echo "Cleaning up XML measure log"
rm -rf $VAR_DIR/measureLog.xml
echo "Cleaning up software measure log"
rm -rf $VAR_DIR/ramfs/*
echo "Cleaning up AIKs"
rm -rf $CONFIG_DIR/aik*

# make /opt/trustagent/configuration/credentials directory
if [[ ! -d $CREDS_DIR ]]; then
  mkdir $CREDS_DIR
  chmod 700 $CREDS_DIR
fi

echo "Re-provisioning the trust agent"
./$SERVICE_NAME setup provision-attestation

echo "Update TA config" #clean garbage value present at last line
sed -i '$d' $CONFIG_DIR/config.yml

echo "Completed $COMPONENT_NAME config upgrade to v4.0.0"
