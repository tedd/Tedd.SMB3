#pragma once

#include <winsock2.h>
#include <ndsupport.h>

constexpr ULONG depth = 8;
constexpr ULONG capacity = 64 * 1024;

// The receive queue owns 'depth' slots; one further slot is borrowed by the reader.
// The last slot is reserved for the single outstanding send.
struct RegisteredBuffers {
    unsigned char* base = nullptr;
    unsigned char* spare = nullptr;

    void attach(unsigned char* storage) {
        base = storage;
        spare = storage + depth * capacity;
    }

    unsigned char* sendSlot() const { return base + (depth + 1) * capacity; }

    template<class Post>
    HRESULT borrow(const ND2_RESULT& item, Post post, ULONG* offset, ULONG* received) {
        if (item.BytesTransferred > capacity) return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        HRESULT hr = post(spare);
        if (FAILED(hr)) return hr;
        spare = static_cast<unsigned char*>(item.RequestContext);
        *offset = static_cast<ULONG>(spare - base);
        *received = item.BytesTransferred;
        return S_OK;
    }
};
