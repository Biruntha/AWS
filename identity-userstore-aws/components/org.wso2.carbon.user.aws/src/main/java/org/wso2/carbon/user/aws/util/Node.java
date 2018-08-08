package org.wso2.carbon.user.aws.util;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author w w w. j a v a g i s t s . c o m
 *
 */
public class Node<T> {

    private T data = null;

    private List<Node<T>> children = new ArrayList<>();

    private Node<T> parent = null;

    public Node(T data) {
        this.data = data;
    }

    public Node<T> addChild(Node<T> child) {
        child.setParent(this);
        this.children.add(child);
        return child;
    }

    public void addChildren(List<Node<T>> children) {
        children.forEach(each -> each.setParent(this));
        this.children.addAll(children);
    }

    public List<Node<T>> getChildren() {
        return children;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    private void setParent(Node<T> parent) {
        this.parent = parent;
    }

    public Node<T> getParent() {
        return parent;
    }

    public Node getRoot() {
        if(parent == null){
            return this;
        }
        return parent.getRoot();
    }

    public static <T> void printTree(Node<T> node, String appender) {
        System.out.println(appender + node.getData());
        node.getChildren().forEach(each ->  printTree(each, appender + appender));
    }
}

//class TreeExample {
//
//    public static void main(String[] args) {
//        Node<String> root = createTree();
//        printTree(root, " ");
//    }
//
//    private static Node<String> createTree() {
//        Node<String> root = new Node<>("root");
//
//        Node<String> node1 = root.addChild(new Node<>("node 1"));
//
//        Node<String> node11 = node1.addChild(new Node<>("node 11"));
//        Node<String> node111 = node11.addChild(new Node<>("node 111"));
//        Node<String> node112 = node11.addChild(new Node<>("node 112"));
//
//        Node<String> node12 = node1.addChild(new Node<>("node 12"));
//
//        Node<String> node2 = root.addChild(new Node<>("node 2"));
//
//        Node<String> node21 = node2.addChild(new Node<>("node 21"));
//        Node<String> node211 = node2.addChild(new Node<>("node 22"));
//        return root;
//    }
//
//    private static <T> void printTree(Node<T> node, String appender) {
//        System.out.println(appender + node.getData());
//        node.getChildren().forEach(each ->  printTree(each, appender + appender));
//    }
//}