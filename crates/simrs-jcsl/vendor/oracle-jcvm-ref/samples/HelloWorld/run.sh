#!/bin/bash
#
# Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.

sample_name=${PWD##*/}
export sample=${sample_name}
samples_dir=$(dirname ${PWD})

echo "Sample name: [${sample_name}]"
echo

client_name=com.oracle.javacard.sample.AMSHelloWorldClient

cap=${samples_dir}/${sample_name}/applet/deliverables/HelloWorld/com/oracle/jcclassic/samples/helloworld/javacard/helloworld.cap
props=${JC_HOME_SIMULATOR}/samples/client.config.properties

client_args="-cap=${cap} -props=${props}"

# Check for optional connection parameter
if [ "$1" != "" ]; then
    host=-host=$1
fi

cd ..
./run.sh ${sample_name} ${client_name} "${client_args}" "${host}"
result=$?
cd ~-

exit ${result}
