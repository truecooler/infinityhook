#pragma once
#include "HipsRequest.h"
#include "HipsResponse.h"
#include "Session.h"

struct HipsSession : Session
{
public:
	//UUID SessionId;

	HipsRequest* Request;
	HipsResponse* Response;

	//bool IsRequestReadByService = false;
};