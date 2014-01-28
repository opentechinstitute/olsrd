#!/bin/bash

if [ ! $# -eq 1 ]; then
  echo "ERROR: specify 1 argument: the mingw gcc"
  exit 1
fi

GCC="$1"
if [ ! -x "$GCC" ]; then
  GCC="$(which "$GCC" | head -1)"
  if [ ! -x "$GCC" ]; then
    echo "ERROR: the mingw gcc ($GCC) is not executable"
    exit 1
  fi
fi

versions=( $("$GCC" -dumpversion | sed -r -e "s/\./ /g") )
while [ ${#versions[*]} -lt 3 ]; do \
  versions[${#versions[*]}]="0"; \
done
if [ ${#versions[*]} -ne 3 ]; then
  echo "WARNING: could not detect the mingw gcc version, setting to 0.0.0"
  versions=( 0 0 0 )
fi

version=$(( versions[0]*10000 + versions[1]*100 + versions[2] ))
echo "$version"
