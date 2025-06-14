#pragma once
#include <ntddk.h>

extern "C" NTSTATUS PsSuspendProcess(IN PEPROCESS Process);
extern "C" NTSTATUS PsResumeProcess(IN PEPROCESS Process);