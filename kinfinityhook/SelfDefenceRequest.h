#pragma once
#include <ntddk.h>
#include "SelfDefenceEvent.h"

struct SelfDefenceRequest
{
public:
    UUID SessionId;

    HANDLE CallerPid;

    HANDLE CalleePid;

    HANDLE CalleeTid;

    ACCESS_MASK DesiredAccess;

    SelfDefenceEvent SelfDefenceEvent;
};