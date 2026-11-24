#pragma once

#include <winsock2.h>
#include <windows.h>
#include <ndsupport.h>

struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};

struct Operation {
    OVERLAPPED ov{};
    Handle event;
    HRESULT init() {
        event.value = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        ov.hEvent = event.value;
        return event.value ? S_OK : HRESULT_FROM_WIN32(GetLastError());
    }
    HRESULT finish(IND2Overlapped* owner, HRESULT status, HANDLE cancel) {
        if (status != ND_PENDING) return status;
        HANDLE handles[] = { event.value, cancel };
        DWORD result = WaitForMultipleObjects(cancel ? 2 : 1, handles, FALSE, INFINITE);
        if (result == WAIT_OBJECT_0) return owner->GetOverlappedResult(&ov, TRUE);
        owner->CancelOverlappedRequests();
        owner->GetOverlappedResult(&ov, TRUE); // Drain before reusing or releasing the OVERLAPPED.
        return HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
    }
};

inline HRESULT completion(IND2CompletionQueue* cq, ND2_RESULT& item, HANDLE cancel) {
    Operation op;
    while (cq->GetResults(&item, 1) == 0) {
        if (!op.event.value) {
            HRESULT hr = op.init();
            if (FAILED(hr)) return hr;
        }
        HRESULT hr = op.finish(cq, cq->Notify(ND_CQ_NOTIFY_ANY, &op.ov), cancel);
        if (FAILED(hr)) return hr;
    }
    return item.Status;
}
