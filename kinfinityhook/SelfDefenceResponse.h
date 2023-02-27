#pragma once
#include <ntddk.h>
#include "Verdict.h"

struct SelfDefenceResponse
{
public:
    UUID SessionId;

    Verdict Verdict;
};