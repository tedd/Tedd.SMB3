// Windows x64 Network Direct v2 provider for in-band SMB Direct messages (RoCE).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wrl/client.h>
#include <initguid.h>
#include "NetworkDirectCompletion.h"
#include "NetworkDirectBuffers.h"
#include <memory>
#include <new>

using Microsoft::WRL::ComPtr;
#define API extern "C" __declspec(dllexport) HRESULT
#define CHECK(call) do { HRESULT result = (call); if (FAILED(result)) return result; } while (false)

// Keep NdStartup alive until all provider objects have been released.
struct Runtime {
    bool started = false;
    HRESULT init() { HRESULT hr = NdStartup(); started = SUCCEEDED(hr); return hr; }
    ~Runtime() { if (started) NdCleanup(); }
};
struct Adapter {
    Runtime runtime;
    ComPtr<IND2Adapter> adapter;
    Handle file;
    HRESULT open(const sockaddr* address, ULONG size) {
        CHECK(runtime.init());
        CHECK(NdOpenAdapter(IID_IND2Adapter, address, size, reinterpret_cast<void**>(adapter.GetAddressOf())));
        return adapter->CreateOverlappedFile(&file.value);
    }
};
struct Listener : Adapter {
    ComPtr<IND2Listener> listener;
};
struct Connection {
    std::shared_ptr<Adapter> owner;
    ComPtr<IND2Connector> connector;
    ComPtr<IND2CompletionQueue> rx, tx;
    ComPtr<IND2MemoryRegion> region;
    ComPtr<IND2QueuePair> pair;
    RegisteredBuffers buffers; // Pinned managed storage owned by the connection SafeHandle.
    bool registered = false;

    HRESULT post(unsigned char* slot) {
        ND2_SGE sge{slot, capacity, region->GetLocalToken()};
        return pair->Receive(slot, &sge, 1);
    }
    HRESULT init(HANDLE cancel) {
        auto* a = owner->adapter.Get();
        HANDLE file = owner->file.value;
        CHECK(a->CreateConnector(IID_IND2Connector, file, reinterpret_cast<void**>(connector.GetAddressOf())));
        CHECK(a->CreateCompletionQueue(IID_IND2CompletionQueue, file, depth, 0, 0, reinterpret_cast<void**>(rx.GetAddressOf())));
        CHECK(a->CreateCompletionQueue(IID_IND2CompletionQueue, file, 1, 0, 0, reinterpret_cast<void**>(tx.GetAddressOf())));
        CHECK(a->CreateQueuePair(IID_IND2QueuePair, rx.Get(), tx.Get(), nullptr, depth, 1, 1, 1, 0, reinterpret_cast<void**>(pair.GetAddressOf())));
        CHECK(a->CreateMemoryRegion(IID_IND2MemoryRegion, file, reinterpret_cast<void**>(region.GetAddressOf())));
        Operation op;
        CHECK(op.init());
        CHECK(op.finish(region.Get(), region->Register(buffers.base, (depth + 2) * capacity, ND_MR_FLAG_ALLOW_LOCAL_WRITE, &op.ov), cancel));
        registered = true;
        for (ULONG i = 0; i < depth; ++i) CHECK(post(buffers.base + i * capacity));
        return S_OK;
    }
    ~Connection() {
        if (pair) pair->Flush();
        connector.Reset();
        pair.Reset();
        rx.Reset();
        tx.Reset();
        if (registered) {
            Operation op;
            if (SUCCEEDED(op.init())) op.finish(region.Get(), region->Deregister(&op.ov), nullptr);
        }
        region.Reset();
    }
};

API smbd_listen(const sockaddr* local, ULONG size, int backlog, USHORT* port, void** result) try {
    auto listener = std::make_shared<Listener>();
    CHECK(listener->open(local, size));
    CHECK(listener->adapter->CreateListener(IID_IND2Listener, listener->file.value, reinterpret_cast<void**>(listener->listener.GetAddressOf())));
    CHECK(listener->listener->Bind(local, size));
    CHECK(listener->listener->Listen(backlog));
    sockaddr_storage bound{};
    ULONG length = sizeof(bound);
    CHECK(listener->listener->GetLocalAddress(reinterpret_cast<sockaddr*>(&bound), &length));
    *port = ntohs(reinterpret_cast<sockaddr_in*>(&bound)->sin_port);
    *result = new std::shared_ptr<Listener>(listener);
    return S_OK;
} catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }

API smbd_accept(void* handle, unsigned char* buffers, ULONG bytes, HANDLE cancel, void** result) try {
    if (!buffers || bytes != (depth + 2) * capacity) return E_INVALIDARG;
    auto& listener = *static_cast<std::shared_ptr<Listener>*>(handle);
    auto connection = std::make_unique<Connection>();
    connection->owner = listener;
    connection->buffers.attach(buffers);
    CHECK(connection->init(cancel));
    Operation op;
    CHECK(op.init());
    CHECK(op.finish(listener->listener.Get(), listener->listener->GetConnectionRequest(connection->connector.Get(), &op.ov), cancel));
    *result = connection.release();
    return S_OK;
} catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }

API smbd_finish_accept(Connection* c, HANDLE cancel) {
    Operation op;
    CHECK(op.init());
    return op.finish(c->connector.Get(), c->connector->Accept(c->pair.Get(), 0, 0, nullptr, 0, &op.ov), cancel);
}

API smbd_connect(const sockaddr* remote, ULONG size, unsigned char* buffers, ULONG bytes, HANDLE cancel, void** result) try {
    if (!buffers || bytes != (depth + 2) * capacity) return E_INVALIDARG;
    auto connection = std::make_unique<Connection>();
    connection->buffers.attach(buffers);
    connection->owner = std::make_shared<Adapter>();
    auto& a = *connection->owner;
    CHECK(a.runtime.init());
    sockaddr_storage storage{};
    auto local = reinterpret_cast<sockaddr*>(&storage);
    SIZE_T length = sizeof(storage);
    CHECK(NdResolveAddress(remote, size, local, &length));
    CHECK(NdOpenAdapter(IID_IND2Adapter, local, length, reinterpret_cast<void**>(a.adapter.GetAddressOf())));
    CHECK(a.adapter->CreateOverlappedFile(&a.file.value));
    CHECK(connection->init(cancel));
    auto* connector = connection->connector.Get();
    CHECK(connector->Bind(local, static_cast<ULONG>(length)));
    Operation op;
    CHECK(op.init());
    CHECK(op.finish(connector, connector->Connect(connection->pair.Get(), remote, size, 0, 0, nullptr, 0, &op.ov), cancel));
    CHECK(op.finish(connector, connector->CompleteConnect(&op.ov), cancel));
    *result = connection.release();
    return S_OK;
} catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }

API smbd_send(Connection* c, ULONG size, HANDLE cancel) {
    if (size > capacity) return E_INVALIDARG;
    auto slot = c->buffers.sendSlot();
    ND2_SGE sge{slot, size, c->region->GetLocalToken()};
    CHECK(c->pair->Send(slot, &sge, 1, 0));
    ND2_RESULT item{};
    return completion(c->tx.Get(), item, cancel);
}

API smbd_receive(Connection* c, HANDLE cancel, ULONG* offset, ULONG* received) {
    ND2_RESULT item{};
    CHECK(completion(c->rx.Get(), item, cancel));
    return c->buffers.borrow(item, [c](unsigned char* spare) { return c->post(spare); }, offset, received);
}

extern "C" __declspec(dllexport) void smbd_close(Connection* c) { delete c; }
extern "C" __declspec(dllexport) void smbd_stop(void* p) { delete static_cast<std::shared_ptr<Listener>*>(p); }
