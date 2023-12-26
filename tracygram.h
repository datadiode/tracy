// Tracy network message structure in terms of a C++ struct template

#pragma once

template<short capacity>
struct TracyGram
{
	// FIXED-LENGTH HEADER
	// C = Console-only flag (Occasionally: Microfilter updatability indicator)
	// S = Severity (11 Bits)
	// I = Trace ID (20 Bits, where 0 indicates text tracing)
	// B = Bitness (0 = 32, 1 = 64) (Occasionally: Hangup request indicator)
	// E = Endianness (0 = LE, 1 = BE)
	// L = Length of payload (14 Bits)
	////////////////////////////////// FEDCBA9876543210FEDCBA9876543210
	u_long tag;						// CSSSSSSSSSSSIIIIIIIIIIIIIIIIIIII
	u_short len;					// ----------------BELLLLLLLLLLLLLL
	// VARIABLE-LENGTH PAYLOAD
	//////////////////////////////////
	union							//
	{								//
		char str[capacity];			// text tracing: readable message text
		u_char buf[capacity];		// binary tracing: serialized va_list
	};								//
	struct hdr_placeholder;
	static hdr_placeholder const &hdr; // used for nothing but to take the size
	__forceinline char *operator &() throw() { return reinterpret_cast<char *>(this); }
};

template<short capacity>
struct TracyGram<capacity>::hdr_placeholder
{
	char placeholder[offsetof(TracyGram<1>, buf)];
};
