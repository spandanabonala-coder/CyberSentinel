#include <stdio.h>
#include <string.h>
#include "stack.h"

#define SIZE 10

char alerts[SIZE][200];
int top = -1;

void pushAlert(char alert[])
{
    if (top == SIZE - 1)
    {
        printf("Alert stack is full!\n");
        return;
    }

    top++;
    strcpy(alerts[top], alert);

    printf("Security alert added to stack!\n");
}

void displayAlerts()
{
    if (top == -1)
    {
        printf("No security alerts stored.\n");
        return;
    }

    printf("\nRecent Security Alerts:\n");

    for (int i = top; i >= 0; i--)
    {
        printf("%s\n", alerts[i]);
    }
}
void getAlerts(char output[], int size)
{
    output[0] = '\0';

    for (int i = top; i >= 0; i--)
    {
        if (strlen(output) + strlen(alerts[i]) + 2 < size)
        {
            strcat(output, alerts[i]);
            strcat(output, "\n");
        }
    }
}