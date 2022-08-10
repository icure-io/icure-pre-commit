#!/bin/bash

has_pre_commit() {
  command -v pre-commit &> /dev/null
  return $?
}

if has_pre_commit ; then
  echo "All required tools are already installed. Run 'pre-commit install' on the root of the repository to install pre-commit hooks."
  exit 0
fi

do_pip() {
  if command -v pip3 $> /dev/null ; then
    command pip3 "$@"
  elif command -v pip &> /dev/null ; then
    command pip "$@"
  else
    echo "ERROR: 'pip' is required to install detect-secrets. Make sure that either 'pip3' or 'pip' is installed and in PATH."
    echo "https://pip.pypa.io/en/stable/installation/"
    exit 1
  fi
}

echo "Installing required tools"

do_pip install pre-commit==2.20.0
retval=$?

if [ $retval -eq 0 ]; then
  echo "Installation successful! Run 'pre-commit install' on the root of the repository to install pre-commit hooks."
else
  echo "ERROR: Installation failed"
  exit $retval
fi
