#!/bin/bash

exit_on_error() {
  if [ $? != 0 ]; then
    echo "$2"
    exit 1
  fi
}

help() {
  echo "
  This is a upgrade script for application agent.
      Steps:
            1. Backup data
            2. Backup initrd
            3. Refresh setup

      Parameters:
       -s | --service  - Service name                # Trustagent service name
       -b | --backup   - Backup folder path          # Folder path for backup, default would be taken as /tmp/
       -h | --help     - Script help                 # Script help
"
  exit 0
}

parse_param() {
  while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
    -s | --service)
      SERVICE_NAME="$2"
      shift 2
      ;;
    -b | --backup)
      BACKUP_PATH="$2"
      shift 2
      ;;
    -h | --help)
      help
      ;;
    *)
      echo "Invalid option provided - $1"
      exit 1
      ;;
    esac
  done
}

main() {
  parse_param "$@"

  TBOOTXM_HOME=/opt/tbootxm
  GENERATED_FILE_LOCATION=/var/tbootxm
  KERNEL_VERSION=`uname -r`
  INITRD_NAME=initrd.img-$KERNEL_VERSION-measurement
  BACKUP_DIR=${BACKUP_PATH}${SERVICE_NAME}_backup

  if [ ! -d $TBOOTXM_HOME ]; then
    echo "tboot-xm is not installed and will not be upgraded"
    exit 0
  fi

  echo "Creating backup directory for application agent ${BACKUP_DIR}/tbootxm"
  mkdir -p ${BACKUP_DIR}/tbootxm
  exit_on_error "Failed to create backup directory for application agent, exiting."

  echo "Backing up application agent to ${BACKUP_DIR}/tbootxm"
  cd $TBOOTXM_HOME && zip -rq tbootxm.zip . && cd -
  mv $TBOOTXM_HOME/tbootxm.zip $BACKUP_DIR/tbootxm/
  exit_on_error "Failed to take backup of application agent, exiting."

  echo "Backing up initrd to ${BACKUP_DIR}/tbootxm"
  cp -f /boot/$INITRD_NAME $BACKUP_DIR/tbootxm/
  exit_on_error "Failed to take backup of initrd, exiting."

  echo "Upgrading application-agent..."
  TBOOTXM_PACKAGE=`ls -1 application-agent*.bin 2>/dev/null | tail -n 1`
  if [ -z "$TBOOTXM_PACKAGE" ]; then
    echo "Failed to find application-agent installer package"
    exit 1
  fi

  export UPGRADE=true
  ./$TBOOTXM_PACKAGE
  exit_on_error "Failed to upgrade application-agent"

  echo "Copying TCB-protection enabled initrd in /boot"
  cp -f $GENERATED_FILE_LOCATION/$INITRD_NAME /boot
  exit_on_error "Failed to copy TCB-protection enabled initrd, exiting."

  echo "Upgrade of application agent completed successfully"
}
main "$@"
