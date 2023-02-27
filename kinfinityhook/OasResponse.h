#pragma once
#include <ntddk.h>
#include "Verdict.h"

struct OasResponse
{
public:
    UUID SessionId;

    Verdict Verdict;
};