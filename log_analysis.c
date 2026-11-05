#include <stdio.h>
#include <string.h>
#include "log_analysis.h"

void analyzeLog(char log[])
{
    if (strstr(log, "FAILED") != NULL)
    {
        printf("WARNING: Failed login detected!\n");
    }
    else if (strstr(log, "ERROR") != NULL)
    {
        printf("WARNING: Security error detected!\n");
    }
    else
    {
        printf("Log appears normal.\n");
    }
}