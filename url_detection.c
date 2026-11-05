#include <stdio.h>
#include <string.h>
#include "url_detection.h"

#define SIZE 20

char urls[SIZE][100];

int hashFunction(char url[])
{
    int sum = 0;

    for (int i = 0; url[i] != '\0'; i++)
        sum += url[i];

    return sum % SIZE;
}

void addURL(char url[])
{
    int index = hashFunction(url);

    for (int i = 0; i < SIZE; i++)
    {
        int position = (index + i) % SIZE;

        if (urls[position][0] == '\0' ||
            strcmp(urls[position], url) == 0)
        {
            strcpy(urls[position], url);
            printf("Suspicious URL added successfully!\n");
            return;
        }
    }

    printf("Hash table is full!\n");
}

int checkURL(char url[])
{
    int index = hashFunction(url);

    for (int i = 0; i < SIZE; i++)
    {
        int position = (index + i) % SIZE;

        if (urls[position][0] == '\0')
            return 0;

        if (strcmp(urls[position], url) == 0)
            return 1;
    }

    return 0;
}

void displayURLs()
{
    printf("\nStored Suspicious URLs:\n");

    for (int i = 0; i < SIZE; i++)
    {
        if (urls[i][0] != '\0')
            printf("%s\n", urls[i]);
    }
}
