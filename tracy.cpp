/*
 * Tracy: A Winsock-based remote tracing tool which uses
 * b8printf.dll to support printf-style binary tracing.
 *
 * Copyright (c) 2018 Jochen Neubeck
 * 
 * Inspired by, and likely reusing code from,
 * https://github.com/NevilleKing/LogOverNet,
 * which is Copyright (c) 2017 Neville King.
 * 
 * SPDX-License-Identifier: MIT
 */
#include <winsock2.h>
#include <windows.h>
#include <shlwapi.h>
#include <commctrl.h>
#include "resource.h"
#include "tracygram.h"

enum
{
	TracyReserved = 20000,
	TracyInfo, TracyWarning, TracyError
};

struct LogMessage
{
	FILETIME timestamp;
	BSTR message;
	UINT id;
	UINT ordinal;
	WORD severity;
	BYTE flags;
	BYTE addrlen;
	SOCKADDR addr;
};

#define DEFAULT_PORT        6881
#define RING_BUFFER_SIZE    0x100000

// Static variables
static LogMessage messages[RING_BUFFER_SIZE];
static UINT receivedMessages = 0;
static UINT listviewMessages = _countof(messages);
static HWND hwndMain = NULL;
static HWND hwndList = NULL;
static HWND hwndCheckList = NULL;
static HFONT hFont = NULL;
static HMENU hMenu = NULL;
static HMENU hCheckListMenu = NULL;
static HBITMAP hDropdownBitmap = NULL;
static HINSTANCE hInstance = NULL;

static int idCheckStateChangeFrom = 0;
static int iCheckStateChangeLower = INT_MAX;
static int iCheckStateChangeUpper = INT_MIN;

static size_t(**bstr8printf)(char *, size_t, const char *, const unsigned char *, size_t) = NULL;

static struct Severity
{
	LPCWSTR text;
	COLORREF color;
};

static Severity const *GetSeverity(WORD severity)
{
	switch (severity)
	{
	case TracyInfo:
		{
			static Severity const instance = { L"INFO", RGB(0x00, 0x00, 0xFF) };
			return &instance;
		}
	case TracyWarning:
		{
			static Severity const instance = { L"WARNING", RGB(0xFF, 0x88, 0x00) };
			return &instance;
		}
	case TracyError:
		{
			static Severity const instance = { L"ERROR", RGB(0xFF, 0x00, 0x00) };
			return &instance;
		}
	}
	return NULL;
}

static BSTR LogFormat(const char *fmt, ...)
{
	char buf[1024];
	va_list va;
	va_start(va, fmt);
	int len = wvnsprintfA(buf, _countof(buf), fmt, va);
	va_end(va);
	return SysAllocStringByteLen(buf, len);
}

static void LogAppend(WORD severity, UINT id, BSTR message, SOCKADDR *sender = NULL, int addrlen = 0, UINT flags = 0)
{
	LogMessage &msg = messages[receivedMessages++ & _countof(messages) - 1];
	msg.ordinal = receivedMessages;
	msg.addrlen = static_cast<BYTE>(addrlen);
	msg.flags = static_cast<BYTE>(flags);
	if (sender)
		msg.addr = *sender;
	GetSystemTimeAsFileTime(&msg.timestamp);
	msg.id = id;
	msg.severity = severity;
	SysFreeString(msg.message);
	msg.message = message;
	InvalidateRect(hwndList, NULL, FALSE);
	if ((receivedMessages & 0xFFF) == 0)
		UpdateWindow(hwndList);
}

static void CALLBACK ReceiveProc(HWND hwnd, UINT, UINT_PTR wParam, DWORD)
{
	SOCKADDR peername;
	int peernamelen = sizeof peername;
	if (getpeername(wParam, &peername, &peernamelen) != 0)
		peernamelen = 0;
	SOCKADDR sockname;
	int socknamelen = sizeof sockname;
	if (getsockname(wParam, &sockname, &socknamelen) == 0)
		reinterpret_cast<SOCKADDR_IN *>(&peername)->sin_port =
		reinterpret_cast<SOCKADDR_IN *>(&sockname)->sin_port;
	TracyGram<2048> msg;
	int len = recv(wParam, &msg, sizeof msg.hdr, 0);
	if (len > 0)
	{
		while (len < sizeof msg.hdr)
		{
			int inc = recv(wParam, &msg + len, sizeof msg.hdr - len, 0);
			if (inc <= 0)
			{
				if ((inc < 0) && (WSAGetLastError() == WSAEWOULDBLOCK))
					continue;
				len = inc;
				break;
			}
			len += inc;
		}
		if ((len > 0) && ((len = (msg.len = ntohs(msg.len)) & 0x3FFF) <= sizeof msg.str))
		{
			int off = 0;
			while (len > 0)
			{
				int inc = recv(wParam, msg.str + off, len, 0);
				if (inc <= 0)
				{
					if ((inc < 0) && (WSAGetLastError() == WSAEWOULDBLOCK))
						continue;
					len = inc;
					break;
				}
				off += inc;
				len -= inc;
			}
			msg.tag = ntohl(msg.tag);
			u_long const opt = (msg.tag >> 20) & 0xFFFUL;
			u_long const id = msg.tag & 0xFFFFFUL;
			if (id || off)
			{
				BSTR const message = SysAllocStringByteLen(msg.str, off);
				LogAppend(static_cast<WORD>(opt), id, message, &peername, peernamelen, (msg.len >> 14) & 3);
				PostMessage(hwnd, WM_TIMER, wParam, reinterpret_cast<LPARAM>(ReceiveProc));
			}
			else if (msg.len == 0x8000) // hangup request
			{
				closesocket(wParam);
				KillTimer(hwnd, wParam);
				LogAppend(TracyInfo, 0, LogFormat("==== Connection closed due to hangup request ===="), &peername, peernamelen);
			}
			else
			{
				u_short const port = ntohs(reinterpret_cast<SOCKADDR_IN *>(&peername)->sin_port);
				SendMessage(hwnd, WM_COMMAND, port, 0); // loads trecepoint dictionary
				SetDlgItemInt(hwnd, port, opt, FALSE);
			}
		}
		else
		{
			closesocket(wParam);
			KillTimer(hwnd, wParam);
			LogAppend(TracyError, 0, LogFormat("==== Connection killed due to malformed message ===="), &peername, peernamelen);
		}
	}
	else if ((len == 0) || (WSAGetLastError() != WSAEWOULDBLOCK))
	{
		closesocket(wParam);
		KillTimer(hwnd, wParam);
		LogAppend(TracyInfo, 0, LogFormat("==== Connection closed ===="), &peername, peernamelen);
	}
	else if (idCheckStateChangeFrom == ntohs(reinterpret_cast<SOCKADDR_IN *>(&peername)->sin_port))
	{
		int const count = iCheckStateChangeUpper - iCheckStateChangeLower + 1;
		LogAppend(TracyInfo, 0, LogFormat("==== MICROFILTER UPDATE: %d ITEMS LEFT ====", count), &peername, peernamelen);
		u_long const opt = GetDlgItemInt(hwnd, idCheckStateChangeFrom, NULL, FALSE);
		if (opt & 0x800) // Does the client accept microfilter updates?
		{
			int len = count * sizeof(u_long);
			if (len > sizeof msg.str)
				len = sizeof msg.str;
			int off = 0;
			while (off < len)
			{
				LVITEM item;
				item.mask = LVIF_PARAM;
				item.iItem = iCheckStateChangeLower;
				item.iSubItem = 0;
				u_long tag = ((opt & 0x7FF) << 20) | ++iCheckStateChangeLower;
				if (iCheckStateChangeLower && ListView_GetItem(hwndCheckList, &item))
					if (*reinterpret_cast<LPCSTR>(item.lParam) == '+')
						tag |= 0x80000000UL;
				*reinterpret_cast<u_long *>(msg.str + off) = htonl(tag);
				off += sizeof(u_long);
			}
			off = 0;
			while (len > 0)
			{
				int inc = send(wParam, msg.str + off, len, 0);
				if (inc <= 0)
				{
					if ((inc < 0) && (WSAGetLastError() == WSAEWOULDBLOCK))
						continue;
					len = inc;
					break;
				}
				off += inc;
				len -= inc;
			}
			if (iCheckStateChangeLower > iCheckStateChangeUpper)
			{
				idCheckStateChangeFrom = 0;
				iCheckStateChangeLower = INT_MAX;
				iCheckStateChangeUpper = INT_MIN;
				LogAppend(TracyInfo, 0, LogFormat("==== MICROFILTER UPDATE FINISHED ===="), &peername, peernamelen);
			}
		}
		else
		{
			idCheckStateChangeFrom = 0;
			iCheckStateChangeLower = INT_MAX;
			iCheckStateChangeUpper = INT_MIN;
			LogAppend(TracyInfo, 0, LogFormat("==== MICROFILTER UPDATE REJECTED ===="), &peername, peernamelen);
		}
	}
}

static void CALLBACK AcceptProc(HWND hwnd, UINT, UINT_PTR wParam, DWORD)
{
	SOCKADDR peername;
	int peernamelen = sizeof peername;
	wParam = accept(wParam, &peername, &peernamelen);
	if (wParam != INVALID_SOCKET)
	{
		// Set the mode of socket to be non-blocking
		u_long iMode = 1;
		ioctlsocket(wParam, FIONBIO, &iMode);
		SOCKADDR sockname;
		int socknamelen = sizeof sockname;
		if (getsockname(wParam, &sockname, &socknamelen) == 0)
			reinterpret_cast<SOCKADDR_IN *>(&peername)->sin_port =
			reinterpret_cast<SOCKADDR_IN *>(&sockname)->sin_port;
		SetTimer(hwnd, wParam, 10, ReceiveProc);
		LogAppend(TracyInfo, 0, LogFormat("==== Client connected ===="), &peername, peernamelen);
	}
}

static const char FileFormatAlignedText[] = "%010u  %-21s  %-23s  %-7ls  %s\r\n";

static void WriteTo(ISequentialStream *pstm, UINT flags, const char *fmt)
{
	int i = -1;
	while ((i = ListView_GetNextItem(hwndList, i, flags)) != -1)
	{
		LogMessage &msg = messages[_countof(messages) - 1 & 
			_countof(messages) - listviewMessages + receivedMessages + i];
		int const port = ntohs(reinterpret_cast<SOCKADDR_IN *>(&msg.addr)->sin_port);
		HWND const hwndCheckList = GetDlgItem(hwndMain, port);
		char sender[22];
		if (DWORD const addrlen = msg.addrlen)
		{
			DWORD len = sizeof sender;
			if (WSAAddressToStringA(&msg.addr, addrlen, NULL, sender, &len) != 0)
				wsprintfA(sender, "ERR#%d", WSAGetLastError());
		}
		else
		{
			*sender = '\0';
		}
		char timestamp[24];
		SYSTEMTIME st;
		if (FileTimeToSystemTime(&msg.timestamp, &st))
		{
			wsprintfA(timestamp, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
				st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
		}
		else
		{
			*timestamp = '\0';
		}
		Severity severity = { NULL, RGB(0, 0, 0) };
		WCHAR severity_text[40];
		if (msg.severity >= TracyReserved)
		{
			if (Severity const *p = GetSeverity(msg.severity))
			{
				severity = *p;
			}
		}
		else if (hwndCheckList)
		{
			if (HWND const hwndHeader = ListView_GetHeader(hwndCheckList))
			{
				if (HMENU const hMenu = reinterpret_cast<HMENU>(GetWindowLongPtr(hwndHeader, GWLP_USERDATA)))
				{
					MENUITEMINFO mii;
					mii.cbSize = sizeof mii;
					mii.fMask = MIIM_STRING | MIIM_DATA;
					mii.cch = _countof(severity_text);
					mii.dwTypeData = severity_text;
					if (GetMenuItemInfo(hMenu, msg.severity | 0x800, FALSE, &mii))
					{
						severity.text = severity_text;
						severity.color = mii.dwItemData;
					}
				}
			}
		}
		if (severity.text == NULL)
		{
			wsprintf(severity_text, L"#%hu", msg.severity);
			severity.text = severity_text;
			severity.color = GetSysColor(COLOR_WINDOWTEXT);
		}
		char message[2048];
		const char *str = reinterpret_cast<const char *>(msg.message);
		if (str)
		{
			int str_len = static_cast<int>(SysStringByteLen(msg.message));
			if (msg.id)
			{
				int len = wsprintfA(message, "%u|", msg.id);
				int port = ntohs(reinterpret_cast<SOCKADDR_IN *>(&msg.addr)->sin_port);
				if (bstr8printf == NULL)
				{
					len += wsprintfA(message + len, "*** bstr8printf() unavailable ***");
				}
				else if (HWND hwndCheckList = GetDlgItem(hwndMain, port))
				{
					char fmt[1024];
					LVITEMA item;
					item.pszText = fmt;
					item.cchTextMax = _countof(fmt);
					item.iSubItem = 2;
					if (SendMessage(hwndCheckList, LVM_GETITEMTEXTA, msg.id - 1, reinterpret_cast<LPARAM>(&item)))
					{
						str_len = bstr8printf[msg.flags & 3](
							message + len, sizeof message  - len, fmt,
							reinterpret_cast<const unsigned char *>(str), str_len);
						if (str_len == 0)
							str_len = wsprintfA(message  + len, "*** bstr8printf() failed ***");
						len += str_len;
					}
				}
				else
				{
					len += wsprintfA(message + len, "*** tracepoint dictionary not loaded ***");
				}
				str = message;
				str_len = len;
			}
		}
		else
		{
			str = "";
		}
		char buf[4096];
		int len = wnsprintfA(buf, sizeof buf,
			msg.timestamp.dwHighDateTime ? fmt : "%010u\r\n",
			msg.ordinal, sender, timestamp, severity.text, str);
		pstm->Write(buf, len, NULL);
	}
}

static void WriteToClipboard(UINT flags, const char *fmt)
{
	if (OpenClipboard(hwndMain))
	{
		IStream *pstm = NULL;
		if (SUCCEEDED(CreateStreamOnHGlobal(NULL, FALSE, &pstm)))
		{
			WriteTo(pstm, flags, fmt);
			pstm->Write("", sizeof(char), NULL);
			HGLOBAL hGlobal = NULL;
			if (EmptyClipboard() && SUCCEEDED(GetHGlobalFromStream(pstm, &hGlobal)) && !SetClipboardData(CF_TEXT, hGlobal))
				GlobalFree(hGlobal);
			pstm->Release();
		}
		CloseClipboard();
	}
}

static void WriteToFile(UINT flags, const char *fmt)
{
	struct : OPENFILENAME
	{
		WCHAR path[MAX_PATH];
	} ofn;
	SecureZeroMemory(&ofn, sizeof ofn);
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = hwndMain;
	ofn.Flags = OFN_OVERWRITEPROMPT;
	ofn.lpstrFile = ofn.path;
	ofn.nMaxFile = _countof(ofn.path);
	ofn.lpstrDefExt = L"log";
	if (GetSaveFileName(&ofn))
	{
		IStream *pstm = NULL;
		if (SUCCEEDED(SHCreateStreamOnFile(ofn.lpstrFile, STGM_WRITE | STGM_CREATE | STGM_SHARE_DENY_WRITE, &pstm)))
		{
			WriteTo(pstm, flags, fmt);
			pstm->Release();
		}
	}
}

static HMENU FindSubMenu(HMENU hMenu, UINT id)
{
	int i = GetMenuItemCount(hMenu);
	while (i > 0)
		if (HMENU hSubMenu = GetSubMenu(hMenu, --i))
			if (GetMenuState(hSubMenu, id, MF_BYCOMMAND) != static_cast<UINT>(-1))
				return hSubMenu;
	return NULL;
}

static void StartServer(LPCWSTR lpCmdLine)
{
	USHORT port = static_cast<USHORT>(StrToInt(lpCmdLine));

	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		LogAppend(TracyError, 0, LogFormat("WSAStartup failed with error: %d", iResult));
		return;
	}

	WCHAR ini[MAX_PATH];
	GetModuleFileName(NULL, ini, _countof(ini));
	PathRenameExtension(ini, L".ini");

	WCHAR buf[8192];
	if (GetPrivateProfileInt(L"WINDOW", L"AlwaysOnTop", 0, ini))
	{
		SetWindowPos(hwndMain, GetWindowLong(hwndMain, GWL_EXSTYLE) & WS_EX_TOPMOST ?
			HWND_NOTOPMOST : HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
	}

	if (port || GetPrivateProfileSection(L"LISTEN", buf, _countof(buf), ini) == 0)
	{
		buf[wsprintf(buf, L"%d", port ? port : DEFAULT_PORT) + 1] = L'\0';
	}

	hMenu = GetMenu(hwndMain);
	hCheckListMenu = FindSubMenu(hMenu, IDM_CHECKLIST_HIDE);

	for (LPCWSTR entry = buf; *entry; entry += lstrlen(entry) + 1)
	{
		port = static_cast<USHORT>(StrToInt(entry));

		if (LPWSTR equals = StrChr(entry, L'='))
		{
			AppendMenu(hCheckListMenu, MFT_RADIOCHECK, port, equals + 1);
		}

		SOCKET ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (ListenSocket == INVALID_SOCKET)
		{
			LogAppend(TracyError, 0, LogFormat("Socket failed with error: %d", WSAGetLastError()));
			continue;
		}

		// Set the mode of socket to be non-blocking
		u_long iMode = 1;
		iResult = ioctlsocket(ListenSocket, FIONBIO, &iMode);
		if (iResult == SOCKET_ERROR)
		{
			LogAppend(TracyError, 0, LogFormat("ioctlsocket failed with error: %d", WSAGetLastError()));
			continue;
		}

		// Setup the TCP listening socket
		SOCKADDR_IN local;
		local.sin_family = AF_INET;
		local.sin_port = htons(port);
		local.sin_addr.s_addr = INADDR_ANY;
		iResult = bind(ListenSocket, reinterpret_cast<SOCKADDR *>(&local), sizeof local);
		if (iResult == SOCKET_ERROR)
		{
			LogAppend(TracyError, 0, LogFormat("bind failed with error: %d", WSAGetLastError()));
			continue;
		}

		iResult = listen(ListenSocket, SOMAXCONN);
		if (iResult == SOCKET_ERROR)
		{
			LogAppend(TracyError, 0, LogFormat("listen failed with error: %d", WSAGetLastError()));
			continue;
		}
		SetTimer(hwndMain, ListenSocket, 100, AcceptProc);
		LogAppend(TracyInfo, 0, LogFormat("Listening on port %d", port));
	}
}

static void GetCellRect(HWND hwnd, int iItem, int iSubItem, RECT &rc)
{
	RECT rch;
	ListView_GetItemRect(hwnd, iItem, &rc, LVIR_BOUNDS);
	ListView_GetSubItemRect(hwnd, iItem, iSubItem, LVIR_LABEL, &rch);
	if (iSubItem != 0)
		rc.left = rch.left;
	rc.right = rch.right;
}

static LRESULT DoCustomDraw(NMLVCUSTOMDRAW *pnm)
{
	static HWND hwndCheckList = NULL;
	static Severity severity = { NULL, RGB(0, 0, 0) };

	RECT rc;

	switch (pnm->nmcd.dwDrawStage)
	{
	case CDDS_PREPAINT:
		return CDRF_NOTIFYITEMDRAW | CDRF_NOTIFYPOSTPAINT;

	case CDDS_ITEM | CDDS_PREPAINT:
		{
			LogMessage &msg = messages[_countof(messages) - 1 & 
				_countof(messages) - listviewMessages + receivedMessages + pnm->nmcd.dwItemSpec];
			int const port = ntohs(reinterpret_cast<SOCKADDR_IN *>(&msg.addr)->sin_port);
			hwndCheckList = GetDlgItem(hwndMain, port);
			UINT state = ListView_GetItemState(pnm->nmcd.hdr.hwndFrom, pnm->nmcd.dwItemSpec, LVIS_SELECTED);
			int syscolor = COLOR_WINDOW;
			severity.text = NULL;
			static WCHAR severity_text[40];
			if (msg.severity >= TracyReserved)
			{
				if (Severity const *p = GetSeverity(msg.severity))
				{
					severity = *p;
				}
			}
			else if (hwndCheckList)
			{
				if (HWND const hwndHeader = ListView_GetHeader(hwndCheckList))
				{
					if (HMENU const hMenu = reinterpret_cast<HMENU>(GetWindowLongPtr(hwndHeader, GWLP_USERDATA)))
					{
						MENUITEMINFO mii;
						mii.cbSize = sizeof mii;
						mii.fMask = MIIM_STRING | MIIM_DATA;
						mii.cch = _countof(severity_text);
						mii.dwTypeData = severity_text;
						if (GetMenuItemInfo(hMenu, msg.severity | 0x800, FALSE, &mii))
						{
							severity.text = severity_text;
							severity.color = mii.dwItemData;
						}
					}
				}
			}
			if (severity.text == NULL)
			{
				wsprintf(severity_text, L"#%hu", msg.severity);
				severity.text = severity_text;
				severity.color = GetSysColor(COLOR_WINDOWTEXT);
			}
			if (pnm->nmcd.hdr.hwndFrom != GetFocus())
			{
				if (state & LVIS_SELECTED)
					syscolor = COLOR_BTNFACE;
				state = 0;
			}
			(state & LVIS_SELECTED ? SetBkColor : SetTextColor)(pnm->nmcd.hdc, severity.color);
			(state & LVIS_SELECTED ? SetTextColor : SetBkColor)(pnm->nmcd.hdc, GetSysColor(syscolor));
		}
		return CDRF_NOTIFYSUBITEMDRAW | CDRF_NOTIFYPOSTPAINT;

	case CDDS_ITEM | CDDS_SUBITEM | CDDS_PREPAINT:
		{
			LogMessage &msg = messages[_countof(messages) - 1 & 
				_countof(messages) - listviewMessages + receivedMessages + pnm->nmcd.dwItemSpec];
			char buf[2048];
			SYSTEMTIME st;
			// Erase the cell's background
			GetCellRect(pnm->nmcd.hdr.hwndFrom, static_cast<DWORD>(pnm->nmcd.dwItemSpec), pnm->iSubItem, rc);
			ExtTextOut(pnm->nmcd.hdc, rc.left, rc.top, ETO_OPAQUE, &rc, NULL, 0, NULL);
			// Draw the cell's content
			switch (msg.timestamp.dwHighDateTime ? pnm->iSubItem : -pnm->iSubItem)
			{
			case 0:
				DrawTextA(pnm->nmcd.hdc, buf, wsprintfA(buf, "%010u", msg.ordinal), &rc, DT_NOPREFIX | DT_SINGLELINE);
				break;
			case 1:
				if (DWORD const addrlen = msg.addrlen)
				{
					DWORD len = sizeof buf;
					if (WSAAddressToStringA(&msg.addr, addrlen, NULL, buf, &len) != 0)
						len = wsprintfA(buf, "ERR#%d", WSAGetLastError());
					DrawTextA(pnm->nmcd.hdc, buf, len, &rc, DT_NOPREFIX | DT_SINGLELINE);
				}
				break;
			case 2:
				if (FileTimeToSystemTime(&msg.timestamp, &st))
				{
					int len = wsprintfA(buf, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
						st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
					DrawTextA(pnm->nmcd.hdc, buf, len, &rc, DT_NOPREFIX | DT_SINGLELINE);
				}
				break;
			case 3:
				DrawTextW(pnm->nmcd.hdc, severity.text, -1, &rc, DT_NOPREFIX | DT_SINGLELINE);
				break;
			case 4:
				if (const char *str = reinterpret_cast<const char *>(msg.message))
				{
					int str_len = static_cast<int>(SysStringByteLen(msg.message));
					if (msg.id)
					{
						int len = wsprintfA(buf, "%u|", msg.id);
						if (bstr8printf == NULL)
						{
							len += wsprintfA(buf + len, "*** bstr8printf() unavailable ***");
						}
						else if (hwndCheckList)
						{
							char fmt[1024];
							LVITEMA item;
							item.pszText = fmt;
							item.cchTextMax = _countof(fmt);
							item.iSubItem = 2;
							if (SendMessage(hwndCheckList, LVM_GETITEMTEXTA, msg.id - 1, reinterpret_cast<LPARAM>(&item)))
							{
								str_len = bstr8printf[msg.flags & 3](
									buf + len, sizeof buf - len, fmt,
									reinterpret_cast<const unsigned char *>(str), str_len);
								if (str_len == 0)
									str_len = wsprintfA(buf + len, "*** bstr8printf() failed ***");
								len += str_len;
							}
						}
						else
						{
							len += wsprintfA(buf + len, "*** tracepoint dictionary not loaded ***");
						}
						str = buf;
						str_len = len;
					}
					DrawTextA(pnm->nmcd.hdc, str, str_len, &rc, DT_NOPREFIX | DT_SINGLELINE);
				}
				break;
			}
		}
		return CDRF_SKIPDEFAULT;

	case CDDS_ITEM | CDDS_POSTPAINT:
		{
			UINT state = ListView_GetItemState(pnm->nmcd.hdr.hwndFrom, pnm->nmcd.dwItemSpec, LVIS_SELECTED | LVIS_FOCUSED);
			if ((state & LVIS_FOCUSED) && (pnm->nmcd.uItemState & CDIS_FOCUS))
			{
				ListView_GetItemRect(pnm->nmcd.hdr.hwndFrom, pnm->nmcd.dwItemSpec, &rc, LVIR_BOUNDS);
				DrawFocusRect(pnm->nmcd.hdc, &rc);
			}
		}
		break;

	case CDDS_POSTPAINT:
		break;
	}
	return CDRF_DODEFAULT;
}

static HWND LoadCheckList(HWND hwndList, LPCWSTR path)
{
	LPSTR lower = NULL;
	LPSTR upper = NULL;
	HANDLE file = NULL;
	DWORD flags = 0;
	LPCWSTR title = PathFindFileName(path);
	do
	{
		struct : OPENFILENAME
		{
			WCHAR path[MAX_PATH];
		} ofn;
		if (file)
		{
			SecureZeroMemory(&ofn, sizeof ofn);
			ofn.lStructSize = sizeof(OPENFILENAME);
			ofn.hwndOwner = hwndMain;
			ofn.Flags = OFN_OVERWRITEPROMPT;
			ofn.lpstrTitle = title;
			ofn.lpstrFile = ofn.path;
			ofn.nMaxFile = _countof(ofn.path);
			path = GetOpenFileName(&ofn) ? ofn.path : NULL;
			flags = ofn.Flags;
		}
		if (path)
		{
			file = CreateFile(path, flags & OFN_READONLY ?
				GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
				FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
		}
	} while (path && file == INVALID_HANDLE_VALUE);
	if (file != INVALID_HANDLE_VALUE)
	{
		DWORD size = GetFileSize(file, NULL);
		if (HANDLE share = CreateFileMapping(flags & OFN_READONLY ? NULL : file, NULL, PAGE_READWRITE, 0, size, NULL))
		{
			lower = static_cast<LPSTR>(MapViewOfFile(share, FILE_MAP_WRITE, 0, 0, 0));
			if (!(flags & OFN_READONLY) || ReadFile(file, lower, size, &flags, NULL) && size == flags)
				upper = lower + size;
			CloseHandle(share);
		}
		CloseHandle(file);
	}
	int iItem = 0;
	LPCSTR p = lower;
	while (p < upper)
	{
		LVITEM item;
		item.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE;
		item.pszText = LPSTR_TEXTCALLBACK;
		item.lParam = reinterpret_cast<LPARAM>(p);
		item.stateMask = LVIS_STATEIMAGEMASK;
		item.state = INDEXTOSTATEIMAGEMASK(1);
		switch (*p)
		{
		case '+':
			item.state = INDEXTOSTATEIMAGEMASK(2);
			// fall through
		case '-':
			item.iItem = iItem++;
			item.iSubItem = 0;
			ListView_InsertItem(hwndList, &item);
			ListView_SetItemState(hwndList, item.iItem, item.state, item.stateMask);
			break;
		default:
			// malformed line -> quit the loop
			upper = NULL;
			break;
		}
		do { } while (*p++ != '\n' && p < upper);
	}
	SetWindowLongPtr(hwndList, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(upper));
	if (upper == NULL)
	{
		// malformed file -> get rid of the garbage
		DestroyWindow(hwndList);
		hwndList = NULL;
		UnmapViewOfFile(lower);
	}
	return hwndList;
}

static LPVOID ShowCheckList(int id, LPVOID preview = NULL)
{
	HWND const hwndList = id ? GetDlgItem(hwndMain, id) : NULL;
	if (hwndCheckList != hwndList)
	{
		if (hwndCheckList)
			ShowWindow(hwndCheckList, SW_HIDE);
		hwndCheckList = hwndList;
	}
	if (id && hwndCheckList == NULL && !preview)
	{
		WCHAR path[2 * MAX_PATH];
		GetModuleFileName(NULL, path, MAX_PATH);
		PathRemoveFileSpec(path);
		LPWSTR name = PathAddBackslash(path);
		GetMenuString(hCheckListMenu, id, name, MAX_PATH, MF_BYCOMMAND);
		hwndCheckList = CreateWindowEx(0, WC_LISTVIEW, NULL,
			WS_CHILD | WS_TABSTOP | LVS_ALIGNLEFT | LVS_SHOWSELALWAYS | LVS_REPORT,
			0, 0, 0, 0, hwndMain, reinterpret_cast<HMENU>(id), hInstance, NULL);
		ListView_SetExtendedListViewStyle(hwndCheckList, LVS_EX_FULLROWSELECT | LVS_EX_CHECKBOXES);
		LVCOLUMN col;
		col.mask = LVCF_WIDTH;
		col.cx = ListView_GetStringWidth(hwndCheckList, L"mmx");
		ListView_InsertColumn(hwndCheckList, 0, &col);
		col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
		col.cx = ListView_GetStringWidth(hwndCheckList, L"00000000m");
		col.fmt = LVCFMT_RIGHT;
		col.pszText = L"ID";
		ListView_InsertColumn(hwndCheckList, 1, &col);
		col.mask = LVCF_TEXT | LVCF_WIDTH;
		col.cx = 15000;
		col.pszText = name;
		ListView_InsertColumn(hwndCheckList, 2, &col);
		if (HWND hwndHeader = ListView_GetHeader(hwndCheckList))
		{
			HDITEM item;
			item.mask = HDI_FORMAT | HDI_BITMAP;
			item.fmt = HDF_BITMAP;
			item.hbm = hDropdownBitmap;
			Header_SetItem(hwndHeader, 0, &item);
		}
		if (PathIsRelative(name))
			name = path;
		hwndCheckList = LoadCheckList(hwndCheckList, name);
		if (hwndCheckList == NULL)
		{
			if (name != path)
				DeleteMenu(hCheckListMenu, id, MF_BYCOMMAND);
		}
		else if (HWND hwndHeader = ListView_GetHeader(hwndCheckList))
		{
			WCHAR ini[MAX_PATH];
			GetModuleFileName(NULL, ini, _countof(ini));
			PathRenameExtension(ini, L".ini");

			WCHAR section[40];
			wsprintf(section, L"%d.SEVERITY", id);

			WCHAR buf[8192];
			if (DWORD len = GetPrivateProfileSection(section, buf, _countof(buf), ini))
			{
				HMENU hMenu = CreatePopupMenu();
				UINT count = 0;
				for (LPWSTR entry = buf; *entry; entry += lstrlen(entry) + 1)
				{
					MENUITEMINFO mii;
					mii.cbSize = sizeof mii;
					mii.fMask = MIIM_ID | MIIM_STRING | MIIM_DATA | MIIM_FTYPE;
					mii.dwTypeData = NULL;
					mii.dwItemData = 0;
					mii.fType = MFT_RIGHTJUSTIFY | MFT_RADIOCHECK;
					mii.wID = StrToInt(entry) | 0x800;
					while (LPWSTR equals = StrChr(entry, L'='))
					{
						entry = equals + 1;
						if (*entry == L'#')
						{
							*equals = L'0';
							*entry = L'x';
							int val = 0;
							if (StrToIntEx(equals, STIF_SUPPORT_HEX, &val))
							{
								mii.dwItemData = RGB(GetBValue(val), GetGValue(val), GetRValue(val));
							}
						}
						else
						{
							mii.dwTypeData = entry;
						}
						*equals = '\0';
					}
					if (!InsertMenuItem(hMenu, count, TRUE, &mii))
						break;
					++count;
				}
				SetWindowLongPtr(hwndHeader, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(hMenu));
			}
		}
	}
	SetWindowPos(hwndMain, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_FRAMECHANGED);
	return preview;
}

static void DoDropFiles(HDROP hDrop)
{
	WCHAR path[MAX_PATH];
	if (DragQueryFile(hDrop, 0, path, _countof(path)))
	{
		static int id = IDM_CHECKLIST_HIDE;
		AppendMenu(hCheckListMenu, MFT_RADIOCHECK, ++id, path);
		ShowCheckList(id);
	}
	DragFinish(hDrop);
}

static void SetSplitPos(int splitpos)
{
	RECT rc;
	GetClientRect(hwndMain, &rc);
	if (hwndCheckList)
	{
		RECT rc2;
		GetWindowRect(hwndCheckList, &rc2);
		MapWindowPoints(NULL, hwndMain, reinterpret_cast<LPPOINT>(&rc2), 2);
		// if the window width changed, re-center the split bar
		if (rc2.right == rc.right)
			MapWindowPoints(hwndCheckList, hwndMain, reinterpret_cast<LPPOINT>(&rc), 1);
		if (splitpos == INT_MAX)
			splitpos = rc.left ? rc.left - 4 : (rc.right - rc.left) / 2;
		if (splitpos > rc.right - 4)
			splitpos = rc.right - 4;
		if (splitpos < 4)
			splitpos = 4;
		SetWindowPos(hwndCheckList, HWND_TOP, splitpos + 4, rc.top, rc.right - splitpos - 4, rc.bottom - rc.top, SWP_SHOWWINDOW);
		rc.left = 0;
		rc.right = splitpos - 4;
	}
	SetWindowPos(hwndList, NULL, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top, SWP_NOZORDER);
}

static void DoWindowPosChanged(WINDOWPOS *pParam)
{
	if ((pParam->flags & (SWP_NOSIZE | SWP_SHOWWINDOW | SWP_FRAMECHANGED)) != SWP_NOSIZE)
	{
		SetSplitPos(INT_MAX);
		ListView_Scroll(hwndList, 0, _countof(messages) << 8);
	}
}

static void DoKeyDown(NMLVKEYDOWN *pParam)
{
	switch (pParam->wVKey)
	{
	case 'C':
		if (GetKeyState(VK_CONTROL) < 0)
			WriteToClipboard(LVNI_SELECTED, FileFormatAlignedText);
		break;
	}
}

static void DoGetDispInfoCheckList(NMLVDISPINFO *pParam)
{
	switch (pParam->item.iSubItem)
	{
	case 1:
		wnsprintfW(pParam->item.pszText, pParam->item.cchTextMax, L"%d", pParam->item.iItem + 1);
		break;
	case 2:
		LPCSTR upper = reinterpret_cast<LPCSTR>(GetWindowLongPtr(pParam->hdr.hwndFrom, GWLP_USERDATA));
		LPCSTR p = reinterpret_cast<LPCSTR>(pParam->item.lParam);
		LPCSTR q = p++;
		do ++q; while (q < upper && *q != '\r');
		int len = MultiByteToWideChar(CP_ACP, 0, p, q - p, pParam->item.pszText, pParam->item.cchTextMax - 1);
		pParam->item.pszText[len] = L'\0';
		break;
	}
}

static void DoItemChangedCheckList(NMLISTVIEW *pParam)
{
	if (pParam->uChanged & LVIF_STATE)
	{
		if ((pParam->uNewState ^ pParam->uOldState) & LVIS_STATEIMAGEMASK)
		{
			UINT const state = pParam->uNewState & LVIS_STATEIMAGEMASK;
			*reinterpret_cast<LPSTR>(pParam->lParam) = state == INDEXTOSTATEIMAGEMASK(2) ? '+' : '-';
			idCheckStateChangeFrom = static_cast<int>(pParam->hdr.idFrom);
			if (iCheckStateChangeLower > pParam->iItem)
				iCheckStateChangeLower = pParam->iItem;
			if (iCheckStateChangeUpper < pParam->iItem)
				iCheckStateChangeUpper = pParam->iItem;
		}
	}
}

static void DoColumnClickCheckList(NMLISTVIEW *pParam)
{
	if (pParam->iSubItem == 0)
	{
		HWND hwndHeader = ListView_GetHeader(pParam->hdr.hwndFrom);
		if (HMENU hMenu = reinterpret_cast<HMENU>(GetWindowLongPtr(hwndHeader, GWLP_USERDATA)))
		{
			int idCheckList = static_cast<int>(pParam->hdr.idFrom);
			u_long const opt = GetDlgItemInt(hwndMain, idCheckList, NULL, FALSE);
			int i = GetMenuItemCount(hMenu);
			while (i)
			{
				--i;
				CheckMenuItem(hMenu, i, GetMenuItemID(hMenu, i) == (opt | 0x800) ?
					MF_CHECKED | MF_BYPOSITION : MF_UNCHECKED | MF_BYPOSITION);
			}
			RECT rc;
			GetWindowRect(hwndHeader, &rc);
			if (int choice = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_NONOTIFY, rc.left, rc.bottom, 0, hwndMain, NULL))
			{
				SetDlgItemInt(hwndMain, idCheckList, (opt & 0x800) | (choice & 0x7FF), FALSE);
				idCheckStateChangeFrom = idCheckList;
				iCheckStateChangeLower = -1;
				iCheckStateChangeUpper = -1;
			}
		}
	}
}

static void DoKeyDownCheckList(NMLVKEYDOWN *pParam)
{
	switch (pParam->wVKey)
	{
	case 'A':
		if (GetKeyState(VK_CONTROL) < 0)
			ListView_SetItemState(pParam->hdr.hwndFrom, -1, LVIS_SELECTED, LVIS_SELECTED);
		break;
	case VK_SPACE:
		int const j = ListView_GetNextItem(pParam->hdr.hwndFrom, -1, LVNI_FOCUSED);
		UINT state = ListView_GetItemState(pParam->hdr.hwndFrom, j, LVIS_SELECTED | LVIS_STATEIMAGEMASK);
		if (state & LVIS_SELECTED)
		{
			int i = -1;
			state ^= INDEXTOSTATEIMAGEMASK(1) ^ INDEXTOSTATEIMAGEMASK(2);
			while ((i = ListView_GetNextItem(pParam->hdr.hwndFrom, i, LVNI_SELECTED)) != -1)
			{
				if (i == j)
					continue;
				ListView_SetItemState(pParam->hdr.hwndFrom, i, state, LVIS_STATEIMAGEMASK);
			}
		}
		break;
	}
}

static INT_PTR CALLBACK WndProcMain(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	static UINT listviewMessages_backup = _countof(messages);
	static HWND hwndCheckList_backup = NULL;

	RECT rc;
	POINT pt;

	switch (message)
	{
	case WM_PARENTNOTIFY:
		switch (LOWORD(wParam))
		{
		case WM_CREATE:
			SendMessage(reinterpret_cast<HWND>(lParam), WM_SETFONT, reinterpret_cast<WPARAM>(hFont), 0);
			break;
		}
		break;
	case WM_NCHITTEST:
		switch (UINT const hittest = static_cast<UINT>(DefDlgProc(hwnd, message, wParam, lParam)))
		{
		case HTCLIENT:
			return HTCAPTION; // Have client area generate SC_MOVE commands
		default:
			return hittest;
		}
		break;
	case WM_NCLBUTTONDBLCLK:
		POINTSTOPOINT(pt, lParam);
		ScreenToClient(hwndMain, &pt);
		if (pt.y < 0)
			break;
		GetClientRect(hwndMain, &rc);
		SetSplitPos((rc.right - rc.left) / 2);
		return 0;
	case WM_SETCURSOR:
		if (LOWORD(lParam) == HTCAPTION)
		{
			GetCursorPos(&pt);
			ScreenToClient(hwndMain, &pt);
			if (pt.y < 0)
				break;
			SetCursor(LoadCursor(NULL, IDC_SIZEWE));
			return TRUE;
		}
		break;
	case WM_SYSCOMMAND:
		switch (wParam & 0xFFF0)
		{
		case SC_MOVE:
			POINTSTOPOINT(pt, lParam);
			ScreenToClient(hwndMain, &pt);
			if (pt.y < 0)
				break;
			SetCapture(hwndMain);
			return 0;
		}
		break;
	case WM_ERASEBKGND:
		GetClientRect(hwndMain, &rc);
		SetBkColor(reinterpret_cast<HDC>(wParam), GetSysColor(COLOR_BTNSHADOW));
		ExtTextOut(reinterpret_cast<HDC>(wParam), 0, 0, ETO_OPAQUE, &rc, NULL, 0, NULL);
		return TRUE;
	case WM_MOUSEMOVE:
		if (GetCapture())
		{
			POINTSTOPOINT(pt, lParam);
			SetSplitPos(pt.x);
		}
		return 0;
	case WM_LBUTTONUP:
		ReleaseCapture();
		break;
	case WM_WINDOWPOSCHANGED:
		DoWindowPosChanged(reinterpret_cast<WINDOWPOS *>(lParam));
		return 0;
	case WM_ENTERIDLE:
		if (wParam == MSGF_MENU)
			SetCursor(LoadCursor(NULL, IDC_ARROW));
		return 0;
	case WM_COMMAND:
		switch (wParam)
		{
		case IDOK:
		case IDCANCEL:
			EndDialog(hwnd, 0);
			break;
		case IDM_TAIL:
		case IDM_TAIL_11:
		case IDM_TAIL_12:
		case IDM_TAIL_13:
		case IDM_TAIL_14:
		case IDM_TAIL_15:
		case IDM_TAIL_16:
		case IDM_TAIL_17:
		case IDM_TAIL_18:
		case IDM_TAIL_19:
		case IDM_TAIL_20:
			if (WPARAM wShift = wParam - IDM_TAIL)
				listviewMessages = 1 << wShift;
			else
				listviewMessages = min(receivedMessages, _countof(messages));
			ListView_SetItemCount(hwndList, listviewMessages);
			if (GetCapture())
				break; // just for preview
			ListView_Scroll(hwndList, 0, _countof(messages) << 8);
			listviewMessages_backup = listviewMessages;
			break;
		case IDM_ALWAYS_ON_TOP:
			SetWindowPos(hwnd, GetWindowLong(hwnd, GWL_EXSTYLE) & WS_EX_TOPMOST ?
				HWND_NOTOPMOST : HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
			break;
		case IDM_EXPORT_SELECTION_TO_CLIPBOARD:
			WriteToClipboard(LVNI_SELECTED, FileFormatAlignedText);
			break;
		case IDM_EXPORT_WHOLE_LOT_TO_FILE:
			WriteToFile(LVNI_ALL, FileFormatAlignedText);
			break;
		case IDM_EXPORT_SELECTION_TO_FILE:
			WriteToFile(LVNI_SELECTED, FileFormatAlignedText);
			break;
		case IDM_CHECKLIST_HIDE:
			wParam = 0;
			// fall through
		default:
			if (HIWORD(wParam) == 0)
			{
				if (ShowCheckList(static_cast<int>(wParam), GetCapture()))
					break; // just for preview
				hwndCheckList_backup = hwndCheckList;
			}
			break;
		}
		break;
	case WM_MENUSELECT:
		if (HIWORD(wParam) & (MF_HELP | MF_SYSMENU))
			break;
		if (listviewMessages != listviewMessages_backup)
		{
			listviewMessages = listviewMessages_backup;
			ListView_SetItemCount(hwndList, listviewMessages);
		}
		if (hwndCheckList != hwndCheckList_backup)
		{
			if (hwndCheckList)
				ShowWindow(hwndCheckList, SW_HIDE);
			hwndCheckList = hwndCheckList_backup;
			if (hwndCheckList)
				ShowWindow(hwndCheckList, SW_SHOW);
			SetSplitPos(INT_MAX);
		}
		ListView_Scroll(hwndList, 0, _countof(messages) << 8);
		if ((HIWORD(wParam) & MF_POPUP) == 0)
			SendMessage(hwndMain, WM_COMMAND, wParam & 0xFFFF, 0);
		break;
	case WM_INITMENUPOPUP:
		if (HIWORD(lParam) == 0)
		{
			HMENU menu = reinterpret_cast<HMENU>(wParam);
			if (CheckMenuItem(menu, IDM_TAIL, listviewMessages == receivedMessages ? MF_CHECKED : MF_UNCHECKED) != 0xFFFFFFFF)
			{
				CheckMenuItem(menu, IDM_TAIL_11, listviewMessages == (1 << 11) ? MF_CHECKED : MF_UNCHECKED);
				CheckMenuItem(menu, IDM_TAIL_12, listviewMessages == (1 << 12) ? MF_CHECKED : MF_UNCHECKED);
				CheckMenuItem(menu, IDM_TAIL_13, listviewMessages == (1 << 13) ? MF_CHECKED : MF_UNCHECKED);
				CheckMenuItem(menu, IDM_TAIL_14, listviewMessages == (1 << 14) ? MF_CHECKED : MF_UNCHECKED);
				CheckMenuItem(menu, IDM_TAIL_15, listviewMessages == (1 << 15) ? MF_CHECKED : MF_UNCHECKED);
				CheckMenuItem(menu, IDM_TAIL_16, listviewMessages == (1 << 16) ? MF_CHECKED : MF_UNCHECKED);
				CheckMenuItem(menu, IDM_TAIL_17, listviewMessages == (1 << 17) ? MF_CHECKED : MF_UNCHECKED);
				CheckMenuItem(menu, IDM_TAIL_18, listviewMessages == (1 << 18) ? MF_CHECKED : MF_UNCHECKED);
				CheckMenuItem(menu, IDM_TAIL_19, listviewMessages == (1 << 19) ? MF_CHECKED : MF_UNCHECKED);
				CheckMenuItem(menu, IDM_TAIL_20, listviewMessages == (1 << 20) ? MF_CHECKED : MF_UNCHECKED);
			}
			else if (CheckMenuItem(menu, IDM_CHECKLIST_HIDE, hwndCheckList == NULL ? MF_CHECKED : MF_UNCHECKED) != 0xFFFFFFFF)
			{
				int i = GetMenuItemCount(menu);
				int idCheckList = hwndCheckList ? GetDlgCtrlID(hwndCheckList) : 0;
				while (--i)
				{
					CheckMenuItem(menu, i, GetMenuItemID(menu, i) == idCheckList ?
						MF_CHECKED | MF_BYPOSITION : MF_UNCHECKED | MF_BYPOSITION);
				}
			}
			else if (CheckMenuItem(menu, IDM_ALWAYS_ON_TOP, GetWindowLong(hwnd, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0xFFFFFFFF)
			{
				C_ASSERT(MF_CHECKED == WS_EX_TOPMOST);
			}
		}
		break;
	case WM_NOTIFY:
		switch (reinterpret_cast<NMHDR *>(lParam)->idFrom)
		{
		case IDC_LIST:
			switch (reinterpret_cast<NMHDR *>(lParam)->code)
			{
			case NM_CUSTOMDRAW:
				return DoCustomDraw(reinterpret_cast<NMLVCUSTOMDRAW *>(lParam));
			case LVN_KEYDOWN:
				DoKeyDown(reinterpret_cast<NMLVKEYDOWN *>(lParam));
				break;
			}
			break;
		default:
			switch (reinterpret_cast<NMHDR *>(lParam)->code)
			{
			case LVN_GETDISPINFO:
				DoGetDispInfoCheckList(reinterpret_cast<NMLVDISPINFO *>(lParam));
				break;
			case LVN_ITEMCHANGED:
				DoItemChangedCheckList(reinterpret_cast<NMLISTVIEW *>(lParam));
				break;
			case LVN_KEYDOWN:
				DoKeyDownCheckList(reinterpret_cast<NMLVKEYDOWN *>(lParam));
				break;
			case LVN_COLUMNCLICK:
				DoColumnClickCheckList(reinterpret_cast<NMLISTVIEW *>(lParam));
				break;
			}
			break;
		}
		return 0;
	case WM_DROPFILES:
		DoDropFiles(reinterpret_cast<HDROP>(wParam));
		return 0;
	}
	return DefDlgProc(hwnd, message, wParam, lParam);
}

static INT_PTR CALLBACK DlgProcMain(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_SETFONT:
		hFont = reinterpret_cast<HFONT>(wParam);
		return TRUE;
	case WM_INITDIALOG:
		SetWindowLongPtr(hwnd, GWLP_WNDPROC, reinterpret_cast<LPARAM>(WndProcMain));
		hwndMain = hwnd;
		hwndList = GetDlgItem(hwndMain, IDC_LIST);
		hDropdownBitmap = reinterpret_cast<HBITMAP>(LoadImage(
			hInstance, MAKEINTRESOURCE(IDB_DROPDOWN), IMAGE_BITMAP,
			0, 0, LR_LOADTRANSPARENT | LR_LOADMAP3DCOLORS));
		if (HANDLE hIcon = LoadImage(hInstance, MAKEINTRESOURCE(IDI_PAW), IMAGE_ICON, 16, 16, LR_SHARED))
			SendMessage(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(hIcon));
		if (HANDLE hIcon = LoadImage(hInstance, MAKEINTRESOURCE(IDI_PAW), IMAGE_ICON, 32, 32, LR_SHARED))
			SendMessage(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(hIcon));
		DragAcceptFiles(hwndMain, TRUE);
		ListView_SetExtendedListViewStyle(hwndList, LVS_EX_FULLROWSELECT);
		LVCOLUMN col;
		col.mask = LVCF_TEXT | LVCF_WIDTH;
		col.cx = ListView_GetStringWidth(hwndList, L"0000000000m");
		col.pszText = L"Ordinal";
		ListView_InsertColumn(hwndList, 0, &col);
		col.cx = ListView_GetStringWidth(hwndList, L"000.000.000.000:00000m");
		col.pszText = L"Sender";
		ListView_InsertColumn(hwndList, 1, &col);
		col.cx = ListView_GetStringWidth(hwndList, L"0000-00-00 00:00:00.000m");
		col.pszText = L"Timestamp";
		ListView_InsertColumn(hwndList, 2, &col);
		col.cx = ListView_GetStringWidth(hwndList, L"WARNINGm");
		col.pszText = L"Severity";
		ListView_InsertColumn(hwndList, 3, &col);
		col.cx = 15000;
		col.pszText = L"Message Text";
		ListView_InsertColumn(hwndList, 4, &col);
		ListView_SetItemCount(hwndList, _countof(messages));
		ShowWindow(hwnd, SW_SHOW);
		ListView_Scroll(hwndList, 0, _countof(messages) << 8);
		StartServer(reinterpret_cast<LPCWSTR>(lParam));
		return TRUE;
	}
	return FALSE;
}

static int Run()
{
	static INITCOMMONCONTROLSEX const icc = { sizeof icc, ICC_LISTVIEW_CLASSES };
	InitCommonControlsEx(&icc);
	OleInitialize(NULL);
	hInstance = GetModuleHandle(NULL);
	if (HINSTANCE dll = LoadLibrary(L"b8printf.dll"))
	{
		reinterpret_cast<FARPROC &>(bstr8printf) = GetProcAddress(dll, "bstr8printf");
	}
	LPWSTR lpCmdLine = GetCommandLine();
	lpCmdLine = PathGetArgs(lpCmdLine);
	int iResult = static_cast<int>(DialogBoxParam(
		hInstance, MAKEINTRESOURCEW(IDD_MAINWINDOW), NULL,
		DlgProcMain, reinterpret_cast<LPARAM>(lpCmdLine)));
	OleUninitialize();
	return iResult;
}

int WINAPI WinMainCRTStartup()
{
	__security_init_cookie();
	ExitProcess(Run());
}
