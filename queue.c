#include <stdio.h>
#include <string.h>
#include "queue.h"

#define SIZE 10

char logs[SIZE][200];

int front = 0;
int rear = -1;
int count = 0;

void enqueueLog(char log[])
{
    if (count == SIZE)
    {
        printf("Log queue is full!\n");
        return;
    }

    rear = (rear + 1) % SIZE;
    strcpy(logs[rear], log);
    count++;

    printf("Security log added to queue!\n");
}

void displayLogs()
{
    if (count == 0)
    {
        printf("No security logs stored.\n");
        return;
    }

    printf("\nSecurity Logs (First In, First Out):\n");

    for (int i = 0; i < count; i++)
    {
        int position = (front + i) % SIZE;
        printf("%s\n", logs[position]);
    }
}

void getLogs(char output[], int size)
{
    output[0] = '\0';

    for (int i = 0; i < count; i++)
    {
        int position = (front + i) % SIZE;

        if (strlen(output) + strlen(logs[position]) + 2 < size)
        {
            strcat(output, logs[position]);
            strcat(output, "\n");
        }
    }
}