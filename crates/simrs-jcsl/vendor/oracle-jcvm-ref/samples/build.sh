#!/bin/bash
#
# Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.

if [ "$1" != "${sample}" ]; then
    echo "Please do not call this script directly"
    echo "Change into desired sample's dir and use script files from there"
    exit 1
fi

if [ "$#" -eq 0 ] || [ "$#" -gt 2 ]; then
    echo "Illegal number of parameters [$#]"
    echo "Usage: build.sh \"sample name\"  (e. g. \"ArrayViews\")"
    echo "   (optional)   \"package list\" (e. g. \"MyShareable ClientApplet ServerApplet\")"
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

# Check environment if JC_HOME_TOOLS is set properly
if [ -z ${JC_HOME_TOOLS} ]; then
    echo "JC_HOME_TOOLS is not set. Please set it to point to latest Java Card Development Kit Tools"
    exit 1
else
    if [ ! -f ${JC_HOME_TOOLS}/lib/tools.jar ]; then
        echo "Invalid environment [JC_HOME_TOOLS]. Please set it to point to latest Java Card Development Kit Tools"
        exit 1
    fi
fi

# Name of generated file list of Java files to be compiled
java_files=java_files.lst

#=======================================================================
# Collect Java files (for applet and client compilation as well)
#=======================================================================
CollectJavaFiles() {
    find . -name "*.java" > ${java_files}
    echo "Java file(s) to be compiled:"
    while IFS= read -r line; do
        echo "  (*) $line"
    done < ${java_files}
}

#=======================================================================
# Look up existing sample and verify that given name ($1) really exists
#=======================================================================
sample_name=${1}
if [ ! -d ${sample_name} ]; then
   echo "Invalid sample name given: [${sample_name}]"
   exit 1
fi

#=================
# Checks complete
#=================

cd ${sample_name}/applet/src

# Collect applet's Java files
CollectJavaFiles

#===============================
# Java compilation of applet(s)
#===============================
echo
echo "Building Java Card applet(s) for: [${sample_name}] ..."
echo

command_javac="${JAVA_HOME}/bin/javac -g -d ../bin -cp ${JC_HOME_TOOLS}/lib/api_classic-3.2.0.jar -source 10 -target 10 -Xlint:-options @${java_files}"
echo Executing [${command_javac}]
echo
${command_javac}
result=$?

rm ${java_files}
cd ~-

# Stop here if Java compilation of applet(s) is not error-free
if [ ${result} -ne 0 ]; then
    echo "Stopping due to error(s) in Java compilation"
    exit ${result}
fi

#========================================================
# Check for ordered package list to be used by converter
#========================================================
cd ${sample_name}/applet

# Make sure output dir for converter is present and empty to allow checking for resulting file(s)
if [ ! -d ./deliverables ]; then
    mkdir ./deliverables
else
    rm -rf ./deliverables/*
fi

package_list=$(realpath "PackageList.lst")
if [ -f ${package_list} ]; then
    rm ${package_list}
fi

# No ordered package list given - create it from existing configuration file(s) instead
if [ -z "${2}" ]; then
    find ${config_path} -name "*.conf" -exec basename {} .conf \; > ${package_list}
else
    for package in $2; do echo ${package} >> ${package_list}; done
fi

cd ~-

#=================
# Converter stage
#=================
echo "Running Java Card converter and verifier..."
echo
echo "Java Card package(s) to be converted and verified:"
for package in $(cat ${package_list}); do echo "  (*) ${package}"; done

cd ${sample_name}/applet/bin

for package in $(cat ${package_list}); do
    echo
    echo "Converting package [$package]..."
    ${JC_HOME_TOOLS}/bin/converter.sh -config ../configurations/${package}.conf
    if [ $? -ne 0 ]; then
        result=$?
        break
    fi

    # Check existence of resulting file [${package}.cap]
    count=$(find ../deliverables -iname "${package}.cap" | wc -l)
    if [ ${count} -eq 0 ]; then
        result=1
        break
    fi

    echo
    echo "Verifying package [$package]..."
    exp_file=$(find ../deliverables -iname "${package}.exp")
    ${JC_HOME_TOOLS}/bin/verifyexp.sh ${exp_file}
    if [ $? -ne 0 ]; then
        result=$?
        break
    fi
done
echo

# Remove automatically created package list file if any, also in error case
if [ -f ${package_list} ]; then
    rm ${package_list}
fi
cd ~-

if [ ${result} -ne 0 ]; then
    exit ${result}
fi

#============================
# Java compilation of client
#============================
echo "Building Java client for [${sample_name}] ..."
echo

cd ${sample_name}/client/src

CollectJavaFiles

command_javac="${JAVA_HOME}/bin/javac -g -d ../bin -cp ${JC_HOME_SIMULATOR}/client/AMService/amservice.jar:${JC_HOME_SIMULATOR}/client/COMService/socketprovider.jar @${java_files}"
echo
echo "Executing: [${command_javac}]"
${command_javac}
result=$?

rm ${java_files}
cd ~-

# Stop here if Java compilation of client is not error-free
if [ ${result} -ne 0 ]; then
    echo "Stopping due to error(s) in Java compilation"
    exit ${result}
fi

echo
echo "Success"

exit ${result}
