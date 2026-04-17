#!/bin/bash
#
# Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.

sample_name=${PWD##*/}
export sample=${sample_name}
package_list="MyShareable ClientApplet ServerApplet"

echo "Sample name: [${sample_name}]"
echo

cd ..
./build.sh ${sample_name} "${package_list}"
result=$?
cd ~-

exit ${result}
