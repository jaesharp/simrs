#!/bin/bash
#
# Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.

sample_name=${PWD##*/}
export sample=${sample_name}
samples_dir=$(dirname ${PWD})

client_name=com.oracle.javacard.sample.ClientObjectDeletion

cap_a=${samples_dir}/${sample_name}/applet/deliverables/packageA/com/oracle/jcclassic/samples/odsample/packageA/javacard/packageA.cap
cap_b=${samples_dir}/${sample_name}/applet/deliverables/packageB/com/oracle/jcclassic/samples/odsample/packageB/javacard/packageB.cap
cap_c=${samples_dir}/${sample_name}/applet/deliverables/libPackageC/com/oracle/jcclassic/samples/odsample/libPackageC/javacard/libPackageC.cap
props=${JC_HOME_SIMULATOR}/samples/client.config.properties

client_args="-capA=${cap_a} -capB=${cap_b} -capC=${cap_c} -props=${props}"

# Check for optional connection parameter
if [ "$1" != "" ]; then
    host=-host=$1
fi

cd ..
./run.sh ${sample_name} ${client_name} "${client_args}" "${host}"
result=$?
cd ~-

exit ${result}
