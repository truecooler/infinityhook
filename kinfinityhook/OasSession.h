#pragma once
#include "OasRequest.h"
#include "OasResponse.h"

struct OasSession : Session
{
public:
	//UUID SessionId;

	OasRequest* Request;
	OasResponse* Response;

	//bool IsRequestReadByService = false;
	
};