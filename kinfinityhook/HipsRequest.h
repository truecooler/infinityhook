#pragma once
#include <ntddk.h>

struct HipsRequest
{
public:
    UUID SessionId;

    HANDLE CallerPid;

    HANDLE CalleePid;

    WCHAR ObjectPath[1024] = {0};
};