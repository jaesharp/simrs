#!/bin/bash
#
# Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.

sample_name=${PWD##*/}
export sample=${sample_name}

echo "Sample name: [${sample_name}]"
echo

cd ..
./build.sh ${sample_name}
result=$?
cd ~-

exit ${result}
