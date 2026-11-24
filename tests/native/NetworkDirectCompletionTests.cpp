#include "NetworkDirectCompletion.h"
#include "NetworkDirectBuffers.h"
#include <array>
#include <cstdio>
#include <stdexcept>
#include <vector>

static void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

// Simulate provider notifications while using real Win32 OVERLAPPED event handles.
class CompletionQueue final : public IND2CompletionQueue {
public:
    HRESULT notification = ND_PENDING;
    HRESULT result = S_OK;
    HRESULT itemStatus = S_OK;
    unsigned emptyPolls = 1;
    bool signalEvent = true;
    unsigned polls = 0, notifications = 0, waits = 0, cancellations = 0;
    OVERLAPPED* pending = nullptr;

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void**) override { return E_NOINTERFACE; }
    ULONG STDMETHODCALLTYPE AddRef() override { return 1; }
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    HRESULT STDMETHODCALLTYPE GetNotifyAffinity(USHORT*, KAFFINITY*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Resize(ULONG) override { return E_NOTIMPL; }
    ULONG STDMETHODCALLTYPE GetResults(ND2_RESULT* items, ULONG count) override {
        require(count == 1 && pending == nullptr, "Polled before draining notification");
        if (++polls <= emptyPolls) return 0;
        items[0].Status = itemStatus;
        items[0].RequestContext = this;
        items[0].BytesTransferred = 1024;
        return 1;
    }
    HRESULT STDMETHODCALLTYPE Notify(ULONG type, OVERLAPPED* ov) override {
        require(type == ND_CQ_NOTIFY_ANY && ov->hEvent != nullptr, "Invalid notification");
        ++notifications;
        if (notification == ND_PENDING) {
            pending = ov;
            if (signalEvent) SetEvent(ov->hEvent);
        }
        return notification;
    }
    HRESULT STDMETHODCALLTYPE CancelOverlappedRequests() override {
        require(pending != nullptr && waits == 0, "Cancelled outside pending operation");
        ++cancellations;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetOverlappedResult(OVERLAPPED* ov, BOOL wait) override {
        require(wait && ov == pending, "Drained a different operation");
        require(signalEvent || cancellations == 1, "Drained before cancellation");
        pending = nullptr;
        ++waits;
        return result;
    }
};

static void completed(ULONG emptyPolls, HRESULT notification, HRESULT itemStatus) {
    CompletionQueue cq;
    cq.emptyPolls = emptyPolls;
    cq.notification = notification;
    cq.itemStatus = itemStatus;
    ND2_RESULT item{};
    require(completion(&cq, item, nullptr) == itemStatus, "Lost completion status");
    require(item.BytesTransferred == 1024 && item.RequestContext == &cq, "Lost work request identity");
    require(cq.notifications == emptyPolls && cq.polls == emptyPolls + 1, "Incorrect rearm count");
    require(cq.waits == (notification == ND_PENDING ? emptyPolls : 0), "Incorrect wait count");
    require(cq.cancellations == 0 && cq.pending == nullptr, "Unexpected cancellation");
}

static void receiveBuffers() {
    std::vector<unsigned char> storage((depth + 2) * capacity);
    RegisteredBuffers buffers;
    buffers.attach(storage.data());
    require(buffers.sendSlot() == storage.data() + storage.size() - capacity, "Incorrect send slot");
    std::array<unsigned char*, depth> posted;
    for (ULONG i = 0; i < depth; ++i) posted[i] = storage.data() + i * capacity;
    unsigned char* previous = storage.data() + depth * capacity;
    for (ULONG i = 0; i < 5 * depth; ++i) {
        ULONG index = (3 * i + 1) % depth;
        auto completedSlot = posted[index];
        ND2_RESULT item{};
        item.RequestContext = completedSlot;
        item.BytesTransferred = i % 2 == 0 ? capacity : i;
        ULONG offset = 0, received = 0;
        require(buffers.borrow(item, [&](unsigned char* slot) {
            require(slot == previous && slot != buffers.sendSlot(), "Incorrect receive repost");
            for (auto active : posted) require(slot != active, "Reposted an outstanding slot");
            posted[index] = slot;
            return S_OK;
        }, &offset, &received) == S_OK, "Borrow failed");
        require(storage.data() + offset == completedSlot && received == item.BytesTransferred, "Incorrect completed slice");
        previous = completedSlot;
    }
    ND2_RESULT item{};
    item.RequestContext = posted.front();
    ULONG offset = 23, received = 42;
    auto failedPost = [&](unsigned char* slot) {
        require(slot == previous, "Lost spare slot");
        return E_FAIL;
    };
    require(buffers.borrow(item, failedPost, &offset, &received) == E_FAIL, "Lost repost failure");
    require(buffers.spare == previous && offset == 23 && received == 42, "Published a failed repost");
    item.BytesTransferred = capacity + 1;
    require(buffers.borrow(item, [](unsigned char*) -> HRESULT {
        throw std::runtime_error("Reposted an oversized completion");
    }, &offset, &received) == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER), "Oversized completion accepted");
    require(buffers.spare == previous && offset == 23 && received == 42, "Published an oversized completion");
}

int main() try {
    receiveBuffers();
    completed(0, ND_PENDING, S_OK);       // Fast path with work already queued.
    completed(1, S_OK, S_OK);            // Notify completes synchronously.
    completed(3, ND_PENDING, S_OK);      // Repeated wakes before the next work completion.
    completed(1, ND_PENDING, E_FAIL);    // The work request itself failed.

    ND2_RESULT item{};
    CompletionQueue failedNotify;
    failedNotify.notification = E_ACCESSDENIED;
    require(completion(&failedNotify, item, nullptr) == E_ACCESSDENIED, "Notify failure lost");
    require(failedNotify.waits == 0 && failedNotify.polls == 1, "Waited on failed submission");

    CompletionQueue failedWait;
    failedWait.result = E_ABORT;
    require(completion(&failedWait, item, nullptr) == E_ABORT, "Pending provider failure lost");
    require(failedWait.waits == 1 && failedWait.polls == 1, "Retried failed notification");

    Handle cancel;
    cancel.value = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    require(cancel.value != nullptr, "CreateEvent failed");
    CompletionQueue cancelled;
    cancelled.signalEvent = false;
    cancelled.result = HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED);
    require(completion(&cancelled, item, cancel.value) == cancelled.result, "Lost cancellation status");
    require(cancelled.cancellations == 1 && cancelled.waits == 1 && cancelled.pending == nullptr,
        "Returned from cancellation with outstanding OVERLAPPED storage");
    return 0;
} catch (const std::exception& error) {
    std::fprintf(stderr, "%s\n", error.what());
    return 1;
}
