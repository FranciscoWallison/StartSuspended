// Undocumented.h (Versão Corrigida e Final)

#pragma once
#include <ntddk.h>

// Declaramos ambas as funções não documentadas que o projeto utiliza.
extern "C" NTSTATUS PsSuspendProcess(IN PEPROCESS Process);
extern "C" NTSTATUS PsResumeProcess(IN PEPROCESS Process);