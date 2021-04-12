#!/bin/bash

COMPONENT_NAME=trustagent
PRODUCT_HOME_DIR=/opt/$COMPONENT_NAME
PRODUCT_BIN_DIR=$PRODUCT_HOME_DIR/bin
CONFIG_DIR=$PRODUCT_HOME_DIR/configuration
CA_CERTS_DIR=$PRODUCT_HOME_DIR/configuration/cacerts
CERTDIR_TRUSTEDJWTCERTS=$PRODUCT_HOME_DIR/configuration/jwt

if [ -z "$SAN_LIST" ]; then
  cp /etc/hostname /proc/sys/kernel/hostname
  export SAN_LIST=$(hostname -i),$(hostname)
  echo $SAN_LIST
fi

if [ ! -f $CONFIG_DIR/.setup_done ]; then
  for directory in $PRODUCT_BIN_DIR $CA_CERTS_DIR $CERTDIR_TRUSTEDJWTCERTS; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chmod 700 $directory
    chmod g+s $directory
  done

  mv /tmp/module_analysis.sh $PRODUCT_BIN_DIR/  && chmod +x $PRODUCT_BIN_DIR/module_analysis.sh
  mv /tmp/module_analysis_da.sh $PRODUCT_BIN_DIR/ && chmod +x $PRODUCT_BIN_DIR/module_analysis_da.sh
  mv /tmp/module_analysis_da_tcg.sh $PRODUCT_BIN_DIR/ && chmod +x $PRODUCT_BIN_DIR/module_analysis_da_tcg.sh

  tagent setup all
  if [ $? -ne 0 ]; then
    exit 1
  fi

  touch $CONFIG_DIR/.setup_done
fi

if [ ! -z "$SETUP_TASK" ]; then
  IFS=',' read -ra ADDR <<< "$SETUP_TASK"
  for task in "${ADDR[@]}"; do
    tagent setup $task --force
    if [ $? -ne 0 ]; then
      exit 1
    fi
  done
fi

tagent init
tagent startService
