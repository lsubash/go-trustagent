#!/bin/sh

# Application Agent install script
# Outline:
# 1.  source the "functions.sh" file:  mtwilson-linux-util.sh
# 2.  force root user installation
# 3.  define application directory layout
# 4.  create application directories and set folder permissions
# 5.  store directory layout in env file
# 6.  install prerequisites
# 7.  unzip tbootxm archive tbootxm-zip-*.zip into TBOOTXM_HOME, overwrite if any files already exist
# 8.  copy utilities script file to application folder
# 9.  run additional setup tasks
# 10. set additional permissions

#####

# Check OS
OS=$(cat /etc/os-release | grep ^ID= | cut -d'=' -f2)
temp="${OS%\"}"
temp="${temp#\"}"
OS="$temp"

# functions script mtwilson-linux-util.sh is required
# we use the following functions:
# echo_failure echo_warning
# define_grub_file install_packages
UTIL_SCRIPT_FILE=$(ls -1 mtwilson-linux-util.sh)
if [ -n "$UTIL_SCRIPT_FILE" ] && [ -f "$UTIL_SCRIPT_FILE" ]; then
  source `pwd`/$UTIL_SCRIPT_FILE
fi

define_grub_file

# enforce root user installation
if [ "$(whoami)" != "root" ]; then
  echo_failure "Running as $(whoami); must install as root"
  exit -1
fi

# define application directory layout
export TBOOTXM_HOME=${TBOOTXM_HOME:-/opt/tbootxm}
export TBOOTXM_BIN=$TBOOTXM_HOME/bin
export TBOOTXM_LIB=$TBOOTXM_HOME/lib
export TBOOTXM_ENV=$TBOOTXM_HOME/env

if [ -z $UPGRADE ]; then
  # create application directories
  for directory in $TBOOTXM_HOME $TBOOTXM_BIN $TBOOTXM_LIB $TBOOTXM_ENV; do
    mkdir -p $directory
    chmod 700 $directory
  done

  # store directory layout in env file
  echo "# $(date)" > $TBOOTXM_ENV/tbootxm-layout
  echo "export TBOOTXM_HOME=$TBOOTXM_HOME" >> $TBOOTXM_ENV/tbootxm-layout
  echo "export TBOOTXM_BIN=$TBOOTXM_BIN" >> $TBOOTXM_ENV/tbootxm-layout
  echo "export TBOOTXM_LIB=$TBOOTXM_LIB" >> $TBOOTXM_ENV/tbootxm-layout

  # make sure zip, unzip and perl are installed
  TBOOTXM_YUM_PACKAGES="zip unzip perl"
  install_packages "TBOOTXM"
  if [ $? -ne 0 ]; then echo_failure "Failed to install prerequisites through package installer"; exit -1; fi
fi

# extract tbootxm  (tbootxm-zip-*.zip)
echo "Extracting application..."
TBOOTXM_ZIPFILE=`ls -1 tbootxm-*.zip 2>/dev/null | head -n 1`
unzip -oq $TBOOTXM_ZIPFILE -d $TBOOTXM_HOME

# copy utilities script file to application folder
cp $UTIL_SCRIPT_FILE $TBOOTXM_HOME/bin/functions.sh

# set permissions
chmod 700 $TBOOTXM_HOME/bin/*

# fix_libcrypto for UBUNTU18.04
# UBUNTU18.04 ISSUE:
# While generating initrd via the installer, the libcrypto.so.1.0.0 library cannot be
# found in /lib/x86_64-linux-gnu. Solution is to create a missing symlink in /lib/x86_64-linux-gnu.
# So in general, what we want to do is:
# 1. identify the location of libcrypto.so.1.0.0 library
# 2. identify which lib directory it's in (/usr/lib/x86_64-linux-gnu, etc)
# 3. create a symlink from /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.0 to /lib/x86_64-linux-gnu/libcrypto.so.1.0.0
fix_libcrypto() {
  local has_libcrypto_lib=`find /lib/x86_64-linux-gnu/ -name libcrypto.so.1.0.0 2>/dev/null | head -1`
  if [ -z "$has_libcrypto_lib" ]; then
    local has_libcrypto=`find / -name libcrypto.so.1.0.0 2>/dev/null | head -1`
    if [ -n "$has_libcrypto" ]; then
      echo "Creating missing symlink for $has_libcrypto"
      ln -s $has_libcrypto /lib/x86_64-linux-gnu/libcrypto.so.1.0.0
    fi
  fi
}

if [ "$OS" == "ubuntu" ]; then
  if [ "$(whoami)" == "root" ]; then
    fix_libcrypto
  fi
fi

# Generate initrd
$TBOOTXM_BIN/generate_initrd.sh
if [ $? -ne 0 ]; then echo_failure "Failed to generate initrd"; exit -1; fi

if [ -z $UPGRADE ]; then
  # Configure host
  $TBOOTXM_BIN/configure_host.sh
  if [ $? -ne 0 ]; then echo_failure "Failed to configure host with tbootxm"; exit -1; fi

  echo "Updating ldconfig for WML library"
  echo "$TBOOTXM_HOME/lib" > /etc/ld.so.conf.d/wml.conf
  ldconfig
  if [ $? -ne 0 ]; then echo_warning "Failed to load ldconfig. Please run command "ldconfig" after installation completes."; fi

  # Added execute permissions for measure binary
  chmod o+x /opt/tbootxm
  chmod o+x /opt/tbootxm/bin/
  chmod o+x /opt/tbootxm/lib/
  chmod o+x /opt/tbootxm/bin/measure
  chmod o+x /opt/tbootxm/lib/libwml.so

  echo_success "Application Agent Installation complete"
fi
