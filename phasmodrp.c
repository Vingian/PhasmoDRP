#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <tchar.h>
#include <time.h>
#include <tlhelp32.h>
#include <shellapi.h>

#include "discord_game_sdk.h"
#include "discord_game_sdk_bin.h"

#ifdef __cplusplus
#define Z3R0 {}
#define ptr_typeof decltype
#else
#define Z3R0 {0}
#define ptr_typeof(x) LPVOID
#endif

#ifndef __thiscall
#define __thiscall __fastcall
#endif

#define Game "Phasmophobia.exe"

#define DiscordID 880395195437428776

HINSTANCE hDLL = NULL;

typedef enum EDiscordResult (*pDiscordCreate)(DiscordVersion version, struct DiscordCreateParams* params, struct IDiscordCore** result);

typedef struct {
	HMODULE sdk;
	struct IDiscordCore *core;
	struct IDiscordActivityManager *activities;
} Discord;

Discord *Discord_Initialize(INT64 ID)
{
	static Discord dsc = Z3R0;

	TCHAR sdk[] = _T("discord_game_sdk.dll");

	if(!dsc.sdk && !(dsc.sdk = LoadLibrary(sdk))) {
		DWORD dwBytesWritten;
		HANDLE hFile = CreateFile(sdk, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		WriteFile(hFile, discord_game_sdk, sizeof(discord_game_sdk), &dwBytesWritten, NULL);
		CloseHandle(hFile);
		dsc.sdk = LoadLibrary(sdk);
	}

	if(dsc.sdk && !dsc.core) {
		struct DiscordCreateParams params;
		DiscordCreateParamsSetDefault(&params);
		params.client_id = ID;
		params.flags = DiscordCreateFlags_NoRequireDiscord;

		pDiscordCreate DC = (pDiscordCreate)GetProcAddress(dsc.sdk, "DiscordCreate");
		if(DC) DC(DISCORD_VERSION, &params, &dsc.core);
	}

	if(dsc.core && !dsc.activities)
		dsc.activities = dsc.core->get_activity_manager(dsc.core);

	return &dsc;
}

void Discord_SetActivity(Discord *dsc, LPCWSTR state, LPCWSTR details, INT party_size, INT party_max, INT64 time)
{
	if(!dsc || !dsc->activities) return;

	struct DiscordActivity activity = Z3R0;
	if(state) _snprintf_s(activity.state, _countof(activity.state), _TRUNCATE, "%ls", state);
	if(details) _snprintf_s(activity.details, _countof(activity.details), _TRUNCATE, "%ls", details);
	if(party_max) {
		activity.party.size.current_size = party_size;
		activity.party.size.max_size = party_max;
	}
	strcpy_s(activity.assets.large_image, _countof(activity.assets.large_image), "icon");
	activity.timestamps.start = time;

	dsc->activities->update_activity(dsc->activities, &activity, NULL, NULL);
}

void Discord_Update(Discord *dsc)
{
	if(dsc && dsc->core)
		dsc->core->run_callbacks(dsc->core);
}

typedef struct {
	DWORD_PTR x,y;
	DWORD l;
	WCHAR s[2];
} SystemString;

#define IL2CPP_API(a,b,c,d,e) static a (*d)b = NULL;                                        \
                              if(!d && !(d = (ptr_typeof(d))GetProcAddress(c, #d))) return e

DWORD_PTR GetMethodAddress(HMODULE ga, LPCSTR spc, LPCSTR cls, LPCSTR mtd, DWORD agc, BOOL ptr)
{
	DWORD_PTR r = 0;

	IL2CPP_API(DWORD_PTR,  (VOID),                      ga, il2cpp_domain_get,                 r);
	IL2CPP_API(DWORD_PTR*, (DWORD_PTR, SIZE_T*),        ga, il2cpp_domain_get_assemblies,      r);
	IL2CPP_API(DWORD_PTR,  (DWORD_PTR),                 ga, il2cpp_assembly_get_image,         r);
	IL2CPP_API(DWORD_PTR,  (DWORD_PTR, LPCSTR, LPCSTR), ga, il2cpp_class_from_name,            r);
	IL2CPP_API(DWORD_PTR*, (DWORD_PTR, LPCSTR, DWORD),  ga, il2cpp_class_get_method_from_name, r);

	DWORD_PTR domain = il2cpp_domain_get();

	SIZE_T len = 0;
	DWORD_PTR *assemblies = (DWORD_PTR*)il2cpp_domain_get_assemblies(domain, &len);

	for(SIZE_T i = 0; i < len && !r; i++) {
		DWORD_PTR image = il2cpp_assembly_get_image(assemblies[i]);
		DWORD_PTR object = il2cpp_class_from_name(image, spc, cls);
		if(object) {
			DWORD_PTR *method = (DWORD_PTR*)il2cpp_class_get_method_from_name(object, mtd, agc);
			r = ptr ? (DWORD_PTR)&method[0] : method[0];
		}
	}

	return r;
}

#define UNITY_API(a,b,c,d) static a (__thiscall *d)b = NULL;                        \
                           if(!d && !(d = (ptr_typeof(d))GetMethodAddress c)) return

HMODULE hGameAssembly = NULL;

void (__thiscall *oriLateUpdate)(DWORD_PTR) = NULL;
void __thiscall myLateUpdate(DWORD_PTR t)
{
	oriLateUpdate(t);

	static DWORD_PTR last_time = 0;
	DWORD current_time = GetTickCount();

	if(current_time - last_time > 500) {
		last_time = current_time;

		UNITY_API(BOOL,      (VOID),      (hGameAssembly, "Photon.Pun",      "PhotonNetwork",      "get_InRoom",          0, 0), GetInRoom);
		UNITY_API(DWORD_PTR, (VOID),      (hGameAssembly, "Photon.Pun",      "PhotonNetwork",      "get_CurrentRoom",     0, 0), GetRoom);
		UNITY_API(BOOL,      (DWORD_PTR), (hGameAssembly, "Photon.Realtime", "Room",               "get_IsVisible",       0, 0), Room_GetIsVisible);
		UNITY_API(INT,       (DWORD_PTR), (hGameAssembly, "Photon.Realtime", "Room",               "get_PlayerCount",     0, 0), Room_GetPlayerCount);
		UNITY_API(INT,       (DWORD_PTR), (hGameAssembly, "Photon.Realtime", "Room",               "get_MaxPlayers",      0, 0), Room_GetMaxPlayers);
		UNITY_API(DWORD_PTR, (VOID),      (hGameAssembly, "Photon.Pun",      "SceneManagerHelper", "get_ActiveSceneName", 0, 0), GetActiveSceneName);

		Discord *dsc = Discord_Initialize(DiscordID);

		static BOOL first_time = TRUE, memInRoom;
		static INT memPlayerCount, memMaxPlayers;
		static WCHAR memSceneName[128], fmtSceneName[128];
		static INT64 timeRoom;

		if(first_time) {
			first_time = FALSE;
			memInRoom = !GetInRoom();
		}

		DWORD_PTR Room;
		if(GetInRoom() && (Room = GetRoom())) {
			BYTE changed = 0;

			if(!memInRoom) { memInRoom = TRUE; changed |= 1<<0; }

			INT PlayerCount = (INT)Room_GetPlayerCount(Room), MaxPlayers = (INT)Room_GetMaxPlayers(Room);
			if(PlayerCount != memPlayerCount) { memPlayerCount = PlayerCount; changed |= 1<<1; }
			if(MaxPlayers != memMaxPlayers) { memMaxPlayers = MaxPlayers; changed |= 1<<2; }

			SystemString *SceneName = (SystemString*)GetActiveSceneName();
			if(SceneName && wcscmp(SceneName->s, memSceneName)) {
				wcscpy_s(memSceneName, _countof(memSceneName), SceneName->s);
				if(!wcscmp(memSceneName, L"Menu_New")) wcscpy_s(fmtSceneName, _countof(fmtSceneName), L"Lobby");
				else {
					for(SIZE_T i = 0; i < _countof(memSceneName); i++)
						if(!(fmtSceneName[i] = memSceneName[i] != '_' ? memSceneName[i] : ' ')) break;
				}
				changed |= 1<<3;
			}

			if(changed) {
				if(changed & (1<<0|1<<3)) timeRoom = time(NULL);
				Discord_SetActivity(dsc, Room_GetIsVisible(Room) ? L"Public" : L"Private", fmtSceneName, memPlayerCount, memMaxPlayers, timeRoom);
			}
		} else {
			if(memInRoom) {
				memInRoom = FALSE;
				Discord_SetActivity(dsc, NULL, L"Menu", 0, 0, time(NULL));
			}
		}

		Discord_Update(dsc);
	}
}

DWORD WINAPI Thread(LPVOID lpParam)
{
	while(hDLL && !(hGameAssembly = GetModuleHandle(_T("GameAssembly")))) Sleep(500);

	if(hDLL) {
		DWORD_PTR *func = (DWORD_PTR*)GetMethodAddress(hGameAssembly, "Photon.Pun", "PhotonHandler", "LateUpdate", 0, 1);
		oriLateUpdate = (ptr_typeof(oriLateUpdate))*func;
		*func = (DWORD_PTR)myLateUpdate;
	}

	return 0;
}

DWORD GetProcessIDByName(PCTSTR name)
{
	DWORD r = 0;
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	if(!name) return r;

	if((hProcessSnap = (HANDLE)CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) != INVALID_HANDLE_VALUE) {
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if(Process32First(hProcessSnap, &pe32))
			do {
				if(!_tcsicmp(pe32.szExeFile, name)) r = pe32.th32ProcessID;
			} while(!r && Process32Next(hProcessSnap, &pe32));
		CloseHandle(hProcessSnap);
	}

	return r;
}

BOOL CheckProcessName(PCTSTR name)
{
	BOOL r = FALSE;
	TCHAR proc[MAX_PATH], *exe = _tcsdup(name);
	if(GetModuleFileName(NULL, proc, _countof(proc))) {
		_tcslwr_s(proc, _tcslen(proc)*sizeof(TCHAR)+sizeof(TCHAR));
		_tcslwr_s(exe, _tcslen(exe)*sizeof(TCHAR)+sizeof(TCHAR));
		if(_tcsstr(proc, exe)) r = TRUE;
	}
	free(exe);
	return r;
}

void ReRunAsAdmin(void)
{
	TCHAR dll[MAX_PATH], pam[MAX_PATH*2];
	if(GetModuleFileName(hDLL, dll, _countof(dll))) {
		_sntprintf_s(pam, _countof(pam), _TRUNCATE, _T("%s,Inject"), dll);
		ShellExecute(NULL, _T("RunAs"), _T("RunDLL32"), pam, NULL, SW_SHOWNORMAL);
	}
}

EXTERN_C __declspec(dllexport) void CALLBACK Inject(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow)
{
	DWORD GamePID = GetProcessIDByName(_T(Game));
	if(GamePID) {
		HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION, FALSE, GamePID);
		if(hProc) {
			TCHAR path[MAX_PATH];
			if(GetModuleFileName(hDLL, path, _countof(path))) {
				TCHAR *mem = (TCHAR*)VirtualAllocEx(hProc, NULL, sizeof(path), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
				if(mem && WriteProcessMemory(hProc, mem, path, sizeof(path), NULL))
					CloseHandle(CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, mem, 0, NULL));
			}
			CloseHandle(hProc);
		} else ReRunAsAdmin();
	} else MessageBox(NULL, _T("Game not found!"), _T("Error"), MB_ICONERROR);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	switch(fdwReason) {
	case DLL_PROCESS_ATTACH:
		hDLL = hinstDLL;
		DisableThreadLibraryCalls(hDLL);
		if(CheckProcessName(_T(Game)))
			CloseHandle(CreateThread(NULL, 0, Thread, NULL, 0, NULL));
		break;
	case DLL_PROCESS_DETACH:
		hDLL = NULL;
	}
	return TRUE;
}

#ifdef NOSTDLIB
EXTERN_C BOOL WINAPI DllMainCRTStartup(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) { return DllMain(hinstDLL, fdwReason, lpReserved); }
#endif
