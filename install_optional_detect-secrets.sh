#!/bin/bash

has_detect_secrets() {
  command -v detect-secrets &> /dev/null
  return $?
}

has_detect_secrets_wordlist() {
  detect-secrets scan -h | grep -- --word-list &> /dev/null
  return $?
}

if has_detect_secrets && has_detect_secrets_wordlist ; then
  echo "Detect-secrets is already installed."
  exit 0
fi

do_pip() {
  if command -v pip &> /dev/null ; then
    command pip "$@"
  elif command -v pip3 $> /dev/null ; then
    command pip3 "$@"
  else
    echo "ERROR: 'pip' is required to install detect-secrets. Make sure that either 'pip' or 'pip3' is installed and in PATH."
    echo "https://pip.pypa.io/en/stable/installation/"
    exit 1
  fi
}

echo "Installing required tools"

do_pip install detect-secrets==1.3.0 pyahocorasick==1.4.4

if ! [[ $? ]] ; then
  exit_val=$?
  echo "ERROR: Installation failed"
  exit $exit_val
fi

if ! has_detect_secrets_wordlist ; then
  echo "ERROR: installation from pip succeeded but '--word-list' argument is not available in detect-secrets: if you had installed detect-secrets through other means try uninstalling it and re-running this script."
  exit 1
fi

echo "Installation successful!"
