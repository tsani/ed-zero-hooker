// Hooker.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

const size_t RPM_BUF_SIZE = 8;
const size_t MSG_BUF_SIZE = 2048;

LPVOID instruction_address = (LPVOID)0x00000000;
LPCWSTR GAME_PATH = L"ED_ZERO.exe";
HANDLE game_process = NULL;
HANDLE game_thread = NULL;
char msg_buf[MSG_BUF_SIZE + 1];
unsigned int msg_offset = 0;

unsigned char int3 = 0xCC;

int last_face_id;
int last_character_id;

enum ParserState
{
	PARSER_READY,
	PARSER_TEXT
};

enum ParserState parser_state = PARSER_READY;

void flush_message_buffer()
{
	if(msg_offset == 0)
		return; // nothing to do !
	// ^ this case can occur at the very beginning of a message right after parsing a face ID but before any text has been parsed
	
	// null-terminate the buffer
	msg_buf[msg_offset] = '\0';

	// allocate a buffer to give to the system with the clipboard data.
	HGLOBAL clip_buf = GlobalAlloc(GMEM_MOVEABLE, msg_offset + 2);

	// copy the message buffer into the global buffer
	memcpy(GlobalLock(clip_buf), msg_buf, msg_offset + 2);
	GlobalUnlock(clip_buf);

	HGLOBAL locale_ptr = GlobalAlloc(GMEM_MOVEABLE, sizeof(DWORD));
	DWORD japanese = 1041;
	memcpy(GlobalLock(locale_ptr), &japanese, sizeof(japanese));
	GlobalUnlock(locale_ptr);
	
	// Write the data to the clipboard.
	if(!OpenClipboard(NULL))
	{
		printf("Failed to open clipboard. (Error %d.)\n", GetLastError());
		goto cleanup;
	}

	if(!EmptyClipboard())
	{
		printf("Failed to empty clipboard. (Error %d.)\n", GetLastError());
		goto cleanup;
	}

	if(!SetClipboardData(CF_TEXT, clip_buf))
	{
		printf("Failed to set clipboard data. (Error %d.)\n", GetLastError());
		goto cleanup;
	}

	if(!SetClipboardData(CF_LOCALE, locale_ptr))
	{
		printf("Failed to set clipboard locale. (Error %d.)\n", GetLastError());
		goto cleanup;
	}

	
cleanup:

	// Clear the message buffer
	ZeroMemory(msg_buf, msg_offset);
	CloseClipboard();
	msg_offset = 0;
}

void parse_character_id(char buf[])
{
	last_character_id = atoi(buf);
}

void parse_face_id(char buf[])
{
	last_face_id = atoi(buf);
}

void parse_hashcode(char buf[])
{
	unsigned int i = 1;
	while(isdigit(buf[i]))
		i++;
	// now i is at the offset of the first non-digit character, so we can see whether we parsed a face or a character id.

	char code = buf[i];
	buf[i] = '\0'; // null-terminate the string so we can parse it nicely
	if(code == 'P')
		parse_character_id(buf + 1);
	else if(code == 'F')
		parse_face_id(buf + 1);
	else
		printf("Parse failure: unknown hashcode %c\n", code);
}

BOOL isbreak(char c)
{
	return c == 0x02
		|| c == 0x03
		|| c == 0x01;
}

void parse_sjis(char buf[])
{
	size_t character_length = (unsigned char)buf[0] >= 0x80 ? 2 : 1;

	if(msg_offset + character_length > MSG_BUF_SIZE)
	{
		printf("Parse failure: message buffer overflow.\n");
		return;
	}

	if(buf[0] == 0x03)
		return;

	if(isbreak(buf[0])) // this is an end-of-line so we translate it to '\n'
	{
		msg_buf[msg_offset] = '\n';
		msg_offset++;
	}
	else
	{
		memcpy(msg_buf + msg_offset, buf, character_length);
		msg_offset += character_length;
	}
}

void parse_buf(char buf[])
{
	switch(parser_state)
	{
	case PARSER_READY:
		if(buf[0] != '#')
		{
			parser_state = PARSER_TEXT;
			parse_buf(buf);
			return;
		}

		parse_hashcode(buf);

		break;

	case PARSER_TEXT:
		if(buf[0] == '#')
		{
			parser_state = PARSER_READY;
			parse_buf(buf);
			return;
		}

		if(buf[0] == '\0') // end of message
		{
			parser_state = PARSER_READY;
			flush_message_buffer();
			return;
		}
		else
			parse_sjis(buf);

		break;
	}
}

void on_breakpoint(HANDLE game_process, HANDLE game_thread)
{
	char sjis[RPM_BUF_SIZE];
	SIZE_T b;
	CONTEXT context;
	LPVOID sjis_addr;
	LPVOID bp_addr;

	// Set a dummy value in EIP so we can check whether the GetThreadContext call actually worked.
	context.Eip = 0xDEADBEEF;

	// We want to read the integer registers (esp. EAX) and the control registers (esp. EIP)
	context.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

	if(!GetThreadContext(game_thread, &context))
	{
		printf("Failed to get thread context.\n");
	}

	// Pull out the breakpoint address and the value of EAX, which is a pointer of the next chunk of data to be parsed
	bp_addr = (LPVOID)context.Eip;
	sjis_addr = (LPVOID)context.Eax;

	// Check that the breakpoint is in fact at the expected location, so we can ignore breakpoints made by other debuggers.
	if(bp_addr != (LPVOID)((DWORD)instruction_address + 1))
	{
		printf("Breakpoint hit at another address, namely 0x%08x.\n", bp_addr);
		return;
	}

	printf("Value of EAX: 0x%08x.\n", sjis_addr);

	if(!ReadProcessMemory(game_process, sjis_addr, sjis, RPM_BUF_SIZE, &b))
	{
		printf("Failed to read SJIS character from game memory @ 0x%08x. Read %d bytes. (Error %d.)\n", sjis_addr, b, GetLastError());
	}
	else
	{
		printf("Read: 0x%02x 0x%02x\n", (unsigned char)sjis[0], (unsigned char)sjis[1]);
	}

	// The instruction that we overwrote was `movzx ecx, byte ptr [eax]`, which is coded on 3 bytes, so we need to jump over the
	// next two bytes which are garbage.
	context.Eip += 2;

	// Reset the context flags to write out in case the call to GetThreadContext changed the flags for some reason.
	context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

	// Simulate the overwritten instruction by moving the lowest read byte into ECX.
	context.Ecx = (unsigned char)sjis[0];

	// Flush the context out to the processor registers.
	if(!SetThreadContext(game_thread, &context))
	{
		printf("Failed to jump over borked instructions.");
		return;
	}

	parse_buf(sjis);
}

void dispatch_event_handler(LPDEBUG_EVENT event)
{
	// We need to skip the first breakpoint event, since it's artificially generated.
	static char first_try = 1;

	switch(event->dwDebugEventCode)
	{
	case EXCEPTION_DEBUG_EVENT:
		// We only bother with the exception events
		switch(event->u.Exception.ExceptionRecord.ExceptionCode)
		{
		case EXCEPTION_BREAKPOINT:
			if(first_try)
			{
				first_try = 0;
				break;
			}

			if(game_thread == NULL)
			{
				if(NULL == (game_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, event->dwThreadId)))
				{
					printf("Failed to open game thread.\n");
					exit(1);
				}
				else
				{
					printf("Game thread opened. Thread ID: %d\n", event->dwThreadId);
				}
			}

			on_breakpoint(game_process, game_thread);
			break;

			default:
				printf("Unhandled exception occurred.\n");
				break;
		}
		break;

	default:
		//printf("Unhandled debug event occurred.\n");
		break;
	}
}

void set_breakpoint(HANDLE game_process)
{
	SIZE_T b;
	DWORD newprot = PAGE_EXECUTE_READWRITE;
	DWORD oldprot;

	if(!VirtualProtectEx(game_process, instruction_address, 1, newprot, &oldprot))
	{
		printf("Failed to weaken memory protection. (Error %d.)\n", GetLastError());
		exit(1);
	}

	printf("Memory protection weakened.\n");

	if(!WriteProcessMemory(game_process, instruction_address, &int3, 1, &b))
	{
		printf("Failed to set breakpoint.\n");
		exit(1);
	}

	printf("Breakpoint set.\n");

	if(!VirtualProtectEx(game_process, instruction_address, 1, oldprot, &newprot))
	{
		printf("Failed to reset memory protection. (Error %d.)\n", GetLastError());
		exit(1);
	}

	printf("Memory protected restored.\n");
}

void debug_loop()
{
	DEBUG_EVENT event;
	ZeroMemory(&event, sizeof(event));

	for(;;)
	{
		if(!WaitForDebugEvent(&event, INFINITE))
		{
			printf("Failed to get next debug event. (Error %d.)", GetLastError());
			exit(1);
		}

		dispatch_event_handler(&event);
		ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
	}
}

void find_game()
{
	HANDLE process_snapshot;
	PROCESSENTRY32 pe;
	char found;

	if(INVALID_HANDLE_VALUE == (process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)))
	{
		printf("Failed to get process list. (Error %d.)\n", GetLastError());
		exit(1);
	}

	pe.dwSize = sizeof(pe);

	if(!Process32First(process_snapshot, &pe))
	{
		printf("Failed to get process from list. (Error %d.)\n", GetLastError());
		exit(1);
	}

	found = 0;
	do
	{
		if(wcscmp(pe.szExeFile, GAME_PATH) == 0)
		{
			found = 1;
			break;
		}
	}
	while(Process32Next(process_snapshot, &pe));

	if(!found)
	{
		printf("Failed to find ED_ZERO.exe; is the game running?\n");
		exit(1);
	}

	printf("Found ED_ZERO.exe\n");

	if(NULL == (game_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID)))
	{
		printf("Failed to open ED_ZERO.exe process. (Error %d.)\n", GetLastError());
		exit(1);
	}

	printf("Opened ED_ZERO.exe process.\n");

	if(!DebugActiveProcess(pe.th32ProcessID))
	{
		printf("Failed to debug ED_ZERO.exe process.\n");
	}

	printf("Debugging ED_ZERO.exe...\n");
}

void escalate_privileges()
{
	HANDLE token;
	LUID debug_luid;

	if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &debug_luid))
	{
		printf("Failed to look up debug privilege name. (Error %d.)\n", GetLastError());
		exit(1);
	}

	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
	{
		printf("Failed to open process access token. (Error %d.)\n", GetLastError());
		exit(1);
	}
	
	PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES)malloc(sizeof(*tp) + sizeof(LUID_AND_ATTRIBUTES));

	tp->PrivilegeCount = 1;
	tp->Privileges[0].Luid = debug_luid;
	tp->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if(!AdjustTokenPrivileges(token, FALSE, tp, sizeof(*tp), NULL, NULL))
	{
		printf("Failed to adjust token privileges. (Error %d.)\n", GetLastError());
		exit(1);
	}

	CloseHandle(token);

	free(tp);
}

int _tmain(int argc, _TCHAR* argv[])
{
	if(argc > 1)
	{
		instruction_address = (LPVOID)(DWORD)_wtoi(argv[1]);
	}

	escalate_privileges();
	printf("Privileges escalated.\n");
	find_game();
	set_breakpoint(game_process);
	printf("Entering debug loop.\n");
	debug_loop();
	getchar();
	return 0;
}