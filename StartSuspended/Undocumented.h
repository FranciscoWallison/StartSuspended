// Undocumented.h (Vers�o Corrigida e Final)

#pragma once
#include <ntddk.h>

// Declaramos ambas as fun��es n�o documentadas que o projeto utiliza.
extern "C" NTSTATUS PsSuspendProcess(IN PEPROCESS Process);
extern "C" NTSTATUS PsResumeProcess(IN PEPROCESS Process);