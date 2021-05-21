#!/bin/bash
# WARNING:
# *** do NOT use TABS for indentation, use SPACES (tabs will cause errors in some linux distributions)
# *** do NOT use 'exit' to return from the functions in this file, use 'return' ONLY (exit will cause unit testing hassles)

# TERM_DISPLAY_MODE can be "plain" or "color"
TERM_DISPLAY_MODE=color
TERM_COLOR_GREEN="\\033[1;32m"
TERM_COLOR_CYAN="\\033[1;36m"
TERM_COLOR_RED="\\033[1;31m"
TERM_COLOR_YELLOW="\\033[1;33m"
TERM_COLOR_NORMAL="\\033[0;39m"

### FUNCTION LIBRARY: terminal display functions

# Environment:
# - TERM_DISPLAY_MODE
# - TERM_DISPLAY_GREEN
# - TERM_DISPLAY_NORMAL
echo_success() {
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_GREEN}"; fi
  echo ${@:-"[  OK  ]"}
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_NORMAL}"; fi
  return 0
}

# Environment:
# - TERM_DISPLAY_MODE
# - TERM_DISPLAY_RED
# - TERM_DISPLAY_NORMAL
echo_failure() {
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_RED}"; fi
  echo ${@:-"[FAILED]"}
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_NORMAL}"; fi
  return 1
}

# Environment:
# - TERM_DISPLAY_MODE
# - TERM_DISPLAY_YELLOW
# - TERM_DISPLAY_NORMAL
echo_warning() {
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_YELLOW}"; fi
  echo ${@:-"[WARNING]"}
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_NORMAL}"; fi
  return 1
}

# Environment:
# - TERM_DISPLAY_MODE
# - TERM_DISPLAY_CYAN
# - TERM_DISPLAY_NORMAL
echo_info() {
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_CYAN}"; fi
  echo ${@:-"[INFO]"}
  if [ "$TERM_DISPLAY_MODE" = "color" ]; then echo -en "${TERM_COLOR_NORMAL}"; fi
  return 1
}

### FUNCTION LIBRARY: file management

# read a property from a property file formatted like NAME=VALUE
# parameters: property name, filename
# example: read_property_from_file MYFLAG FILENAME
# Automatically strips Windows carriage returns from the file
read_property_from_file() {
  local property="${1}"
  local filename="${2}"
  if [ -f "$filename" ]; then
    local found=`cat "$filename" | grep "^$property"`
    if [ -n "$found" ]; then
      echo `cat "$filename" | tr -d '\r' | grep "^$property" | head -n 1 | awk -F '=' '{ print $2 }'`
    fi
  fi
}

# write a property into a property file, replacing the previous value
# parameters: property name, filename, new value
# example: update_property_in_file MYFLAG FILENAME true
update_property_in_file() {
  local property="${1}"
  local filename="${2}"
  local value="${3}"

  if [ -f "$filename" ]; then
    local ispresent=`grep "^${property}" "$filename"`
    if [ -n "$ispresent" ]; then
      # first escape the pipes new value so we can use it with replacement command, which uses pipe | as the separator
      local escaped_value=`echo "${value}" | sed 's/|/\\|/g'`
      # replace just that line in the file and save the file
      updatedcontent=`sed -re "s|^(${property})\s*=\s*(.*)|\1=${escaped_value}|" "${filename}"`
      # protect against an error
      if [ -n "$updatedcontent" ]; then
        echo "$updatedcontent" > "${filename}"
      else
        echo_warning "Cannot write $property to $filename with value: $value"
        echo -n 'sed -re "s|^('
        echo -n "${property}"
        echo -n ')=(.*)|\1='
        echo -n "${escaped_value}"
        echo -n '|" "'
        echo -n "${filename}"
        echo -n '"'
        echo
      fi
    else
      # property is not already in file so add it. extra newline in case the last line in the file does not have a newline
      echo "" >> "${filename}"
      echo "${property}=${value}" >> "${filename}"
    fi
  else
    # file does not exist so create it
    echo "${property}=${value}" > "${filename}"
  fi
}

### FUNCTION LIBRARY: package management

# check if a command is already on path
is_command_available() {
  which $* > /dev/null 2>&1
  local result=$?
  if [ $result -eq 0 ]; then return 0; else return 1; fi
}  

install_packages() {
  local component=${1}
  local yum_packages=$(eval "echo \$${component}_YUM_PACKAGES")
  for package in ${yum_packages}; do
    echo "Installing ${package}..."
    yum -y install ${package}
    if [ $? -ne 0 ]; then echo_failure "Failed to install ${package}"; return 1; fi
  done
}

### FUNCTION LIBRARY: grub
is_uefi_boot() {
  if [ -d /sys/firmware/efi ]; then
    return 0
  else
    return 1
  fi
}

define_grub_file() {
  if is_uefi_boot; then
    if [ -f "/boot/efi/EFI/redhat/grub.cfg" ]; then
      DEFAULT_GRUB_FILE="/boot/efi/EFI/redhat/grub.cfg"
    else
      DEFAULT_GRUB_FILE="/boot/efi/EFI/ubuntu/grub.cfg"
    fi
  else
    if [ -f "/boot/grub2/grub.cfg" ]; then
      DEFAULT_GRUB_FILE="/boot/grub2/grub.cfg"
    else
      DEFAULT_GRUB_FILE="/boot/grub/grub.cfg"
    fi
  fi
  export GRUB_FILE=${GRUB_FILE:-$DEFAULT_GRUB_FILE}
}

### FUNCTION LIBRARY: sUEFI
is_suefi_enabled() {
  bootctl status | grep 'Secure Boot: enabled' > /dev/null
  if [ $? -eq 0 ]; then
    return 0
  fi
  return 1
}
