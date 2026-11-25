// Exercise the actual queue code with deterministic completions and post failures.
#include "../../../src/native/linux-rdma/smbdirect.c"
#include <stdio.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "line %d: %s\n", __LINE__, #expr); exit(1); } } while (0)

static uint8_t slots[(depth + 2) * capacity];
static struct ibv_wc next_wc;
static int poll_result, post_error, posts;
static unsigned last_slot, send_size;
static struct ibv_context context;
static struct ibv_qp qp = {.context = &context};
static struct ibv_cq cq = {.context = &context};
static struct ibv_mr mr = {.lkey = 42};
static struct rdma_cm_id id = {.qp = &qp};

static int mock_poll(struct ibv_cq *which, int count, struct ibv_wc *wc)
{
    CHECK(which == &cq && count == 1);
    *wc = next_wc;
    return poll_result;
}

static int mock_receive(struct ibv_qp *which, struct ibv_recv_wr *wr, struct ibv_recv_wr **bad)
{
    (void)bad;
    CHECK(which == &qp && wr->wr_id <= depth && wr->next == NULL && wr->num_sge == 1);
    CHECK(wr->sg_list->addr == (uintptr_t)(slots + wr->wr_id * capacity));
    CHECK(wr->sg_list->length == capacity && wr->sg_list->lkey == mr.lkey);
    last_slot = (unsigned)wr->wr_id;
    ++posts;
    return post_error;
}

static int mock_send(struct ibv_qp *which, struct ibv_send_wr *wr, struct ibv_send_wr **bad)
{
    (void)bad;
    CHECK(which == &qp && wr->opcode == IBV_WR_SEND && wr->send_flags == IBV_SEND_SIGNALED);
    CHECK(wr->next == NULL && wr->num_sge == 1);
    CHECK(wr->sg_list->addr == (uintptr_t)(slots + (depth + 1) * capacity));
    CHECK(wr->sg_list->length == send_size && wr->sg_list->lkey == mr.lkey);
    ++posts;
    return post_error;
}

static void test_receive(struct connection *c)
{
    unsigned offset, bytes;
    poll_result = 1;
    next_wc.opcode = IBV_WC_RECV;
    for (unsigned i = 0; i < 1000; ++i) {
        unsigned slot = i % (depth + 1), spare = c->spare;
        next_wc.wr_id = slot;
        next_wc.byte_len = i % 2 ? capacity : i;
        CHECK(smbd_linux_receive(c, &offset, &bytes) == 0);
        CHECK(offset == slot * capacity && bytes == next_wc.byte_len && c->spare == slot && last_slot == spare);
    }

    unsigned spare = c->spare;
    int before = posts;
    next_wc.wr_id = spare;
    CHECK(smbd_linux_receive(c, &offset, &bytes) == EIO);
    next_wc.wr_id = depth + 1;
    CHECK(smbd_linux_receive(c, &offset, &bytes) == EIO);
    next_wc.wr_id = (spare + 1) % (depth + 1);
    next_wc.byte_len = capacity + 1;
    CHECK(smbd_linux_receive(c, &offset, &bytes) == EIO);
    next_wc.byte_len = capacity;
    next_wc.opcode = IBV_WC_SEND;
    CHECK(smbd_linux_receive(c, &offset, &bytes) == EIO);
    next_wc.opcode = IBV_WC_RECV;
    next_wc.status = IBV_WC_WR_FLUSH_ERR;
    CHECK(smbd_linux_receive(c, &offset, &bytes) == EIO);
    CHECK(c->spare == spare && posts == before);

    next_wc.status = IBV_WC_SUCCESS;
    post_error = ENOMEM;
    CHECK(smbd_linux_receive(c, &offset, &bytes) == ENOMEM && c->spare == spare);
    post_error = 0;
}

static void test_send(struct connection *c)
{
    const unsigned lengths[] = {0, 1, capacity - 1, capacity};
    next_wc.opcode = IBV_WC_SEND;
    for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        send_size = lengths[i];
        CHECK(smbd_linux_send(c, send_size) == 0);
    }
    int before = posts;
    CHECK(smbd_linux_send(c, capacity + 1) == EINVAL && posts == before);
    poll_result = -1;
    CHECK(smbd_linux_send(c, send_size) == EIO);
    post_error = ENOSPC;
    CHECK(smbd_linux_send(c, send_size) == ENOSPC);
}

static void test_wait(struct connection *c)
{
    int ready = eventfd(0, EFD_CLOEXEC), disconnect = eventfd(1, EFD_CLOEXEC);
    CHECK(ready >= 0 && disconnect >= 0);
    CHECK(wait_fd(ready, c->cancel_fd, disconnect) == ECONNRESET);
    CHECK(eventfd_write(ready, 1) == 0);
    CHECK(wait_fd(ready, c->cancel_fd, disconnect) == 0);
    smbd_linux_cancel(c);
    CHECK(wait_fd(ready, c->cancel_fd, disconnect) == ECANCELED);
    CHECK(wait_fd(-1, c->cancel_fd, -1) == ECANCELED);
    close(ready);
    close(disconnect);
}

int main(void)
{
    struct connection *c;
    CHECK(smbd_linux_create(NULL, sizeof(slots), &c) == EINVAL && !c);
    CHECK(smbd_linux_create(slots, sizeof(slots) - 1, &c) == EINVAL && !c);
    CHECK(smbd_linux_create(slots, sizeof(slots), &c) == 0);
    CHECK(smbd_linux_connect(c, NULL, 0) == EINVAL);
    struct sockaddr_in ipv4 = {.sin_family = AF_INET};
    struct sockaddr_in6 ipv6 = {.sin6_family = AF_INET6};
    CHECK(address_valid((struct sockaddr *)&ipv4, sizeof(ipv4)));
    CHECK(address_valid((struct sockaddr *)&ipv6, sizeof(ipv6)));
    CHECK(!address_valid((struct sockaddr *)&ipv4, sizeof(ipv6)));
    context.ops.poll_cq = mock_poll;
    context.ops.post_recv = mock_receive;
    context.ops.post_send = mock_send;
    c->mr = &mr;
    c->id = &id;
    c->rx.cq = c->tx.cq = &cq;
    test_receive(c);
    test_send(c);
    test_wait(c);
    c->mr = NULL;
    c->id = NULL;
    c->rx.cq = c->tx.cq = NULL;
    smbd_linux_close(c);
    puts("Linux RDMA queue tests passed");
    return 0;
}
