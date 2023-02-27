#pragma once

#include "SelfDefenceRequest.h"
#include "SelfDefenceResponse.h"
#include "Session.h"

struct SelfDefenceSession : Session
{
public:
	//UUID SessionId;

	SelfDefenceRequest* Request;
	SelfDefenceResponse* Response;

	//bool IsRequestReadByService = false;

};