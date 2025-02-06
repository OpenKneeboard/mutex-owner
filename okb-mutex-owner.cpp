// Copyright 2025 Fred Emmott <fred@fredemmott.com>
// SPDX-License-Identifier: LGPL-2.1
#include <Windows.h>
#include <winternl.h>

#include "wine-nt.h"

#include <winrt/base.h>

#include <bit>
#include <span>
#include <print>

#pragma comment(lib, "ntdll.lib")


constexpr auto ObjectNameInformation = static_cast<OBJECT_INFORMATION_CLASS>(1);
constexpr auto SystemHandleInformation = static_cast<SYSTEM_INFORMATION_CLASS>(16);
constexpr NTSTATUS STATUS_INFO_LENGTH_MISMATCH = 0xc0000004;

__kernel_entry NTSYSCALLAPI NTSTATUS NtQueryObject(
        HANDLE Handle,
        OBJECT_INFORMATION_CLASS ObjectInformationClass,
        PVOID ObjectInformation,
        ULONG ObjectInformationLength,
        PULONG ReturnLength
);


std::vector<SYSTEM_HANDLE_ENTRY> GetHandleInformation() {
    auto byteCount = 0x10000;
    auto info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(malloc(byteCount));
    memset(info, 0, byteCount);
    while (NtQuerySystemInformation(SystemHandleInformation, info, byteCount, nullptr) == STATUS_INFO_LENGTH_MISMATCH) {
        byteCount *= 2;
        info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(realloc(info, byteCount));
    }
    const auto count = info->Count;
    std::vector<SYSTEM_HANDLE_ENTRY> ret;
    ret.reserve(count);
    std::ranges::copy(std::span(info->Handle, count), std::back_inserter(ret));
    free(info);
    return ret;
}

int main(int argc, char **argv) {
    auto ntdll = LoadLibraryW(L"ntdll.dll");
    auto f_NtQueryObject = reinterpret_cast<decltype(&NtQueryObject)>(GetProcAddress(ntdll, "NtQueryObject"));

    const auto handles = GetHandleInformation();

    bool matched = false;

    for (auto&& entry: handles) {
        char rawBuffer[1024 * sizeof(wchar_t)]{};
        auto nameInfo = reinterpret_cast<OBJECT_NAME_INFORMATION *>(rawBuffer);

        winrt::handle proc{
                OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, false, entry.OwnerPid)};
        if (!proc) {
            continue;
        }

        winrt::handle dup;
        DuplicateHandle(proc.get(), reinterpret_cast<HANDLE>(entry.HandleValue), GetCurrentProcess(), dup.put(),
                        STANDARD_RIGHTS_READ, false, 0);
        if (!dup) {
            continue;
        }

        char typeInfoBuf[1024] {};
        auto& typeInfo = reinterpret_cast<PUBLIC_OBJECT_TYPE_INFORMATION&>(typeInfoBuf);
        f_NtQueryObject(dup.get(), ObjectTypeInformation, &typeInfo, sizeof(typeInfoBuf), nullptr);
        constexpr std::wstring_view File { L"File"};
        if (typeInfo.TypeName.Buffer == File) {
            // Querying ObjectNameInformation for Files hangs.
            continue;
        }

        f_NtQueryObject(dup.get(), ObjectNameInformation, nameInfo, sizeof(rawBuffer), nullptr);
        if (nameInfo->Name.Length == 0) {
            continue;
        }
        std::wstring_view name{nameInfo->Name.Buffer, nameInfo->Name.Length / sizeof(wchar_t)};
        if (!(name.contains(L"OpenKneeboard") || name.contains(L"openkneeboard"))) {
            continue;
        }

        std::wstring processPath;
        DWORD processPathSize = 32767;
        processPath.resize(processPathSize);
        QueryFullProcessImageNameW(proc.get(), 0, processPath.data(), &processPathSize);
        processPath.resize(processPathSize);

        std::println("{}", winrt::to_string(std::format(L"{} `{}` is owned by process {}:\n  {}", typeInfo.TypeName.Buffer, name, entry.OwnerPid, processPath)));
        matched = true;
    }

    if (!matched) {
        std::println("No OpenKneeboard named resources found");
    }

    return 0;
}
