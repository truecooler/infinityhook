#pragma once
#include <ntddk.h>


struct OasRequest
{
public:
    UUID SessionId;

    HANDLE CallerPid;

    WCHAR ObjectPath[1024];

    ACCESS_MASK DesiredAccess;
};