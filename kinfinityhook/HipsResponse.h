#pragma once
#include <ntddk.h>
#include "Verdict.h"


struct HipsResponse
{
public:
    UUID SessionId;

    Verdict Verdict;
};