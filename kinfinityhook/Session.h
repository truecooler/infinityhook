#pragma once
#include <ntddk.h>
#include "ProtectionType.h"

struct Session
{
	UUID SessionId;

	ProtectionType ProtectionType;

	bool IsRequestReadByService = false;
};