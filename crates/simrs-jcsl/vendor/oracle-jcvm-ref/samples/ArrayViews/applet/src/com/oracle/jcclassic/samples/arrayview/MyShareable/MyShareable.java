/**
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 *
 */

package com.oracle.jcclassic.samples.arrayview.MyShareable;

import javacard.framework.Shareable;

public interface MyShareable extends Shareable {
    // the shareable interface includes only one method
    // for providing the ArrayView to the server
    public byte handleRscView(byte[] rsc);
}
