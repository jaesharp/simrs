/**
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 *
 */

/*
 */

package com.oracle.jcclassic.samples.odsample.packageB;

/**
 * Class represents node in a tree contained in B.java
 */
public class BTreeNode {
    private short data;

    public BTreeNode(short data) {
        this.data = data;
    }

    public void setData(short d){
        data= d;
    }
    public short getData(){
        return data;
    }
}
