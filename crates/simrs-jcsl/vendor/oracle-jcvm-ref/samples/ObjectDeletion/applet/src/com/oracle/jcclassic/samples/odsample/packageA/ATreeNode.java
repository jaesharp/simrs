/**
 * Copyright (c) 1998, 2025, Oracle and/or its affiliates. All rights reserved.
 *
 */

/*
 */

package com.oracle.jcclassic.samples.odsample.packageA;

/**
 * Class represents nodes of a binary tree.
 */

public class ATreeNode {

    ATreeNode left = null;
    ATreeNode right = null;
    private static short data = (byte)0xAA;

    /**
     * Constructor. Makes children if depth of tree not reached maxdepth yet
     */
    public ATreeNode(short currDepth, short maxDepth) {
        if (currDepth < maxDepth) {
            left = new ATreeNode((short) (currDepth + 1), maxDepth);
            right = new ATreeNode((short) (currDepth + 1), maxDepth);
        }
    }

    public ATreeNode getLeft() {
		return left;
	}

	public ATreeNode getRight() {
		return right;
	}

	public static void setData(short d) {
        data = d;
    }

    public static short getData() {
        return data;
    }
}
