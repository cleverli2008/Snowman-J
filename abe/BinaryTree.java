package abe;

/*
 * author: licong
 */

import java.util.LinkedList;

public class BinaryTree {
	public static enum NodeType{ AND, OR, LEAF }
	
	public static void preOrderTraversal(TreeNode root){
		if(root == null){
			return;
		}
		System.out.println(root);
		preOrderTraversal(root.left);
		preOrderTraversal(root.right);
	}
	
	public static void postOrderTraversal(TreeNode root){
		if(root == null){
			return;
		}
		postOrderTraversal(root.left);
		postOrderTraversal(root.right);
		System.out.println(root);
	}

	public static void inOrderTraversal(TreeNode root){
		if(root == null){
			return;
		}
		inOrderTraversal(root.left);
		System.out.println(root);
		inOrderTraversal(root.right);
	}

	public static void updateParentPointer(TreeNode root){ 
		TreeNode p = root;
		TreeNode left = root.getLeft();
		TreeNode right = root.getRight();
		if(left != null){
			left.setParent(p);
			updateParentPointer(left);
		}
		if(right != null){
			right.setParent(p);
			updateParentPointer(right);
		}
	}

	public static class TreeNode{  
		private NodeType type;
		private String value;	// for leaf node
		private TreeNode parent;
		private TreeNode left;
		private TreeNode right;
		private LinkedList<Integer> vector;
		
		public LinkedList<Integer> getVector() {
			return vector;
		}
		public void setVector(LinkedList<Integer> vector) {
			this.vector = vector;
		}
		public TreeNode getParent() {
			return parent;
		}
		public void setParent(TreeNode parent) {
			this.parent = parent;
		}
		public String getValue() {
			return value;
		}
		public void setValue(String value) {
			this.value = value;
		}
		public NodeType getType() {
			return type;
		}
		public void setType(NodeType type) {
			this.type = type;
		}
		public TreeNode getLeft() {
			return left;
		}
		public void setLeft(TreeNode left) {
			this.left = left;
		}
		public TreeNode getRight() {
			return right;
		}
		public void setRight(TreeNode right) {
			this.right = right;
		}
		
		public String toString(){
			return this.type == NodeType.LEAF ? 
				   this.type + ":" + this.value :
				   this.type.toString();
		}
	}
}
