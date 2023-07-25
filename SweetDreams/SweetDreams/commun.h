#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include <string.h>
#include <time.h>
#include <tlhelp32.h>
#include <vector>

#include "Sleepy.h"
#include "crypto.h"
#include "stompingStuff.h"
#include "getData.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)