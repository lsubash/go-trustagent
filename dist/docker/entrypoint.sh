#!/bin/bash

SECRETS=/etc/secrets
IFS=$'\r\n' GLOBIGNORE='*' command eval 'secretFiles=($(ls  $SECRETS))'
for i in "${secretFiles[@]}"; do
    export $i=$(cat $SECRETS/$i)
done

COMPONENT_NAME=trustagent
PRODUCT_HOME_DIR=/opt/$COMPONENT_NAME
PRODUCT_BIN_DIR=$PRODUCT_HOME_DIR/bin
CONFIG_DIR=$PRODUCT_HOME_DIR/configuration
CA_CERTS_DIR=$PRODUCT_HOME_DIR/configuration/cacerts
CERTDIR_TRUSTEDJWTCERTS=$PRODUCT_HOME_DIR/configuration/jwt
CREDENTIALS_DIR=$CONFIG_DIR/credentials

if [ -z "$SAN_LIST" ]; then
  cp /etc/hostname /proc/sys/kernel/hostname
  export SAN_LIST=$(hostname -i),$(hostname)
  echo $SAN_LIST
fi

if  [ ! -z "$TA_SERVICE_MODE" ] && [ "$TA_SERVICE_MODE" == "outbound" ]; then
  export TA_HOST_ID=$(hostname)
fi

if [ ! -f $CONFIG_DIR/.setup_done ]; then
  for directory in $PRODUCT_BIN_DIR $CA_CERTS_DIR $CERTDIR_TRUSTEDJWTCERTS $CREDENTIALS_DIR; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chmod 700 $directory
    chmod g+s $directory
  done

  tagent setup all
  if [ $? -ne 0 ]; then
    exit 1
  fi

  touch $CONFIG_DIR/.setup_done
fi

if [ ! -z "$SETUP_TASK" ]; then
  cp $CONFIG_DIR/config.yml /tmp/config.yml
  IFS=',' read -ra ADDR <<< "$SETUP_TASK"
  for task in "${ADDR[@]}"; do
    tagent setup $task --force
    if [ $? -ne 0 ]; then
      cp /tmp/config.yml $CONFIG_DIR/config.yml
      exit 1
    fi
  done
  rm -rf /tmp/config.yml
fi

for i in "${secretFiles[@]}"; do
    unset $i
done

tagent init
tagent startService
