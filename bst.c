#include <stdio.h>
#include <stdlib.h>
#include "bst.h"

struct Node
{
    int severity;
    struct Node *left;
    struct Node *right;
};

struct Node *root = NULL;

struct Node *createNode(int severity)
{
    struct Node *newNode =
        (struct Node *)malloc(sizeof(struct Node));

    newNode->severity = severity;
    newNode->left = NULL;
    newNode->right = NULL;

    return newNode;
}

struct Node *insert(struct Node *node, int severity)
{
    if (node == NULL)
        return createNode(severity);

    if (severity < node->severity)
        node->left = insert(node->left, severity);
    else if (severity > node->severity)
        node->right = insert(node->right, severity);

    return node;
}

void insertAlert(int severity)
{
    root = insert(root, severity);
    printf("Alert severity added to BST!\n");
}

void inorder(struct Node *node)
{
    if (node == NULL)
        return;

    inorder(node->left);
    printf("%d ", node->severity);
    inorder(node->right);
}

void displayAlertsBST()
{
    printf("Alert severities in sorted order: ");
    inorder(root);
    printf("\n");
}
void inorderToString(struct Node *node, char output[],
                     int size, int *used)
{
    if (node == NULL || *used >= size - 1)
        return;

    inorderToString(node->left, output, size, used);

    if (*used < size - 1)
    {
        int written = snprintf(output + *used,
                               size - *used,
                               "%d ", node->severity);

        if (written > 0)
            *used += written;

        if (*used >= size)
            *used = size - 1;
    }

    inorderToString(node->right, output, size, used);
}

void getBSTAlerts(char output[], int size)
{
    output[0] = '\0';

    int used = 0;

    inorderToString(root, output, size, &used);
}