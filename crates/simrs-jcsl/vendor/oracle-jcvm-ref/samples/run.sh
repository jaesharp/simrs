#!/bin/bash
#
# Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.

#=======================================================================
# Expected arguments:
#   $1 : Sample name (e. g. ArrayViews)
#   $2 : Client name (e. g. ClientArrayViews)
#   $3 : Client args (cap file(s) and configuration file)
#=======================================================================

if [ "$1" != "${sample}" ]; then
    echo "Please do not call this script directly"
    echo "Change into desired sample's dir and use script files from there"
    exit 1
fi

if [ "$#" -lt 3 ]; then
    echo "Illegal number of parameters"
    exit 1
fi

# Check environment if JAVA_HOME is set properly
if [ -z ${JAVA_HOME} ]; then
    echo "JAVA_HOME is not set. Please set it to point to JDK 17"
    exit 1
fi

# Check environment if JC_HOME_SIMULATOR is set properly
if [ -z ${JC_HOME_SIMULATOR} ]; then
    echo "JC_HOME_SIMULATOR is not set. Please set it to point to latest Java Card Development Kit Simulator"
    exit 1
else
    if [ ! -d ${JC_HOME_SIMULATOR}/runtime/bin ]; then
        echo "Invalid environment [JC_HOME_SIMULATOR]. Please set it to point to latest Java Card Development Kit Simulator"
        exit 1
    fi
fi

#=======================================================================
# Look up existing sample and verify that given name ($1) really exists
#=======================================================================
sample_name=${1}
if [ ! -d ${sample_name} ]; then
   echo "Invalid sample name given: [${sample_name}]"
   exit 1
fi

client_name=${2}
client_args=${3}

#=================
# Checks complete
#=================

echo "Sample name   : [${sample_name}]"
echo "Client name   : [${client_name}]"
if [ "$4" != "" ]; then
    host=\"$4\"
    echo "Connect param : [${host}]"
fi
echo "Parameter list:"
for arg in ${client_args}; do
    echo " ${arg}"
done

cd ${sample_name}/client/bin
ext_modulepath="${JC_HOME_SIMULATOR}/client/AMService:${JC_HOME_SIMULATOR}/client/COMService"

command_java="${JAVA_HOME}/bin/java \
-p ${JC_HOME_SIMULATOR}/client/AMService/amservice.jar:${JC_HOME_SIMULATOR}/client/COMService/socketprovider.jar \
--module-path ${ext_modulepath} --add-modules ALL-MODULE-PATH ${client_name} ${client_args} ${host}"

echo
echo "Executing: [${command_java}]"
echo
eval "${command_java}"
result=$?

if [ ${result} -eq 0 ]; then
    echo "Success"
else
    echo "Failed"
fi

exit ${result}
