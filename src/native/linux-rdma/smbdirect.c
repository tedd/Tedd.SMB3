// Linux in-band SMB Direct over reliable connected RoCE queue pairs.
#include <arpa/inet.h>
#include <errno.h>
#include <infiniband/verbs.h>
#include <poll.h>
#include <rdma/rdma_cma.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

enum { depth = 8, capacity = 65536, cm_timeout_ms = 5000 };

struct listener {
    struct rdma_event_channel *channel;
    struct rdma_cm_id *id;
};

struct completion_queue {
    struct ibv_comp_channel *channel;
    struct ibv_cq *cq;
};

struct connection {
    struct rdma_event_channel *channel;
    struct rdma_cm_id *id;
    struct ibv_mr *mr;
    struct completion_queue rx, tx;
    uint8_t *slots;
    unsigned spare;
    int cancel_fd;
    int awaiting_accept;
    int established;
};

// One level-triggered eventfd per connection interrupts every outstanding wait.
static int wait_fd(int fd, int cancel_fd, int cm_fd)
{
    struct pollfd fds[] = {{fd, POLLIN, 0}, {cancel_fd, POLLIN, 0}, {cm_fd, POLLIN, 0}};
    int n;
    do { n = poll(fds, 3, -1); } while (n < 0 && errno == EINTR);
    if (n < 0) return errno;
    if (fds[1].revents) return ECANCELED;
    if (fds[0].revents & POLLIN) return 0;
    return ECONNRESET;
}

void smbd_linux_cancel(struct connection *c)
{
    uint64_t one = 1;
    while (write(c->cancel_fd, &one, sizeof(one)) < 0 && errno == EINTR) {}
}

int smbd_linux_create(uint8_t *slots, unsigned bytes, struct connection **out)
{
    *out = NULL;
    if (!slots || bytes != (depth + 2) * capacity) return EINVAL;
    struct connection *c = calloc(1, sizeof(*c));
    if (!c) return ENOMEM;
    c->cancel_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (c->cancel_fd < 0) { int err = errno; free(c); return err; }
    c->slots = slots;
    c->spare = depth;
    *out = c;
    return 0;
}

static void destroy_cq(struct completion_queue *q)
{
    if (q->cq) ibv_destroy_cq(q->cq);
    if (q->channel) ibv_destroy_comp_channel(q->channel);
}

void smbd_linux_close(struct connection *c)
{
    if (c->awaiting_accept) rdma_reject(c->id, NULL, 0);
    if (c->established) rdma_disconnect(c->id);
    if (c->id && c->id->qp) rdma_destroy_qp(c->id);
    if (c->mr) ibv_dereg_mr(c->mr);
    destroy_cq(&c->tx);
    destroy_cq(&c->rx);
    if (c->id) rdma_destroy_id(c->id);
    if (c->channel) rdma_destroy_event_channel(c->channel);
    close(c->cancel_fd);
    free(c);
}

static int create_cq(struct ibv_context *device, unsigned count, struct completion_queue *q)
{
    q->channel = ibv_create_comp_channel(device);
    if (!q->channel) return errno;
    q->cq = ibv_create_cq(device, count, NULL, q->channel, 0);
    if (!q->cq) return errno;
    return ibv_req_notify_cq(q->cq, 0);
}

static int post_receive(struct connection *c, unsigned slot)
{
    struct ibv_sge sge = {.addr = (uintptr_t)(c->slots + slot * capacity), .length = capacity, .lkey = c->mr->lkey};
    struct ibv_recv_wr wr = {.wr_id = slot, .sg_list = &sge, .num_sge = 1};
    struct ibv_recv_wr *bad;
    return ibv_post_recv(c->id->qp, &wr, &bad);
}

static int prepare(struct connection *c)
{
    struct ibv_context *device = c->id->verbs;
    if (!device) return ENODEV;
    if (device->device->transport_type != IBV_TRANSPORT_IB) return EPROTONOSUPPORT;
    int err = create_cq(device, depth, &c->rx);
    if (err) return err;
    err = create_cq(device, 1, &c->tx);
    if (err) return err;
    struct ibv_qp_init_attr attr = {
        .qp_type = IBV_QPT_RC, .send_cq = c->tx.cq, .recv_cq = c->rx.cq,
        .cap = {.max_send_wr = 1, .max_recv_wr = depth, .max_send_sge = 1, .max_recv_sge = 1}
    };
    if (rdma_create_qp(c->id, NULL, &attr)) return errno;
    c->mr = ibv_reg_mr(c->id->pd, c->slots, (depth + 2) * capacity, IBV_ACCESS_LOCAL_WRITE);
    if (!c->mr) return errno;
    for (unsigned i = 0; i < depth; ++i) {
        err = post_receive(c, i);
        if (err) return err;
    }
    return 0;
}

static int cm_event(struct rdma_event_channel *channel, int cancel_fd, enum rdma_cm_event_type expected,
                    struct rdma_cm_id **child)
{
    int err = wait_fd(channel->fd, cancel_fd, -1);
    if (err) return err;
    struct rdma_cm_event *event;
    if (rdma_get_cm_event(channel, &event)) return errno;
    if (event->status) err = event->status < 0 ? -event->status : event->status;
    else if (event->event != expected) err = ECONNABORTED;
    if (!err && child) *child = event->id;
    rdma_ack_cm_event(event);
    return err;
}

static int address_valid(const struct sockaddr *address, unsigned bytes)
{
    return address && ((bytes == sizeof(struct sockaddr_in) && address->sa_family == AF_INET) ||
                       (bytes == sizeof(struct sockaddr_in6) && address->sa_family == AF_INET6));
}

static int established(struct connection *c)
{
    int err = cm_event(c->channel, c->cancel_fd, RDMA_CM_EVENT_ESTABLISHED, NULL);
    if (!err) c->established = 1;
    return err;
}

int smbd_linux_connect(struct connection *c, struct sockaddr *peer, unsigned bytes)
{
    if (!address_valid(peer, bytes)) return EINVAL;
    c->channel = rdma_create_event_channel();
    if (!c->channel) return errno;
    if (rdma_create_id(c->channel, &c->id, NULL, RDMA_PS_TCP)) return errno;
    if (rdma_resolve_addr(c->id, NULL, peer, cm_timeout_ms)) return errno;
    int err = cm_event(c->channel, c->cancel_fd, RDMA_CM_EVENT_ADDR_RESOLVED, NULL);
    if (err) return err;
    if (rdma_resolve_route(c->id, cm_timeout_ms)) return errno;
    err = cm_event(c->channel, c->cancel_fd, RDMA_CM_EVENT_ROUTE_RESOLVED, NULL);
    if (err) return err;
    err = prepare(c);
    if (err) return err;
    struct rdma_conn_param params = {.retry_count = 7, .rnr_retry_count = 7};
    if (rdma_connect(c->id, &params)) return errno;
    return established(c);
}

void smbd_linux_stop(struct listener *l)
{
    if (l->id) rdma_destroy_id(l->id);
    if (l->channel) rdma_destroy_event_channel(l->channel);
    free(l);
}

int smbd_linux_listen(struct sockaddr *address, unsigned bytes, int backlog, uint16_t *port, struct listener **out)
{
    *out = NULL;
    if (!address_valid(address, bytes)) return EINVAL;
    struct listener *l = calloc(1, sizeof(*l));
    if (!l) return ENOMEM;
    l->channel = rdma_create_event_channel();
    if (!l->channel || rdma_create_id(l->channel, &l->id, NULL, RDMA_PS_TCP) ||
        rdma_bind_addr(l->id, address) || rdma_listen(l->id, backlog)) {
        int err = errno;
        smbd_linux_stop(l);
        return err;
    }
    *port = ntohs(rdma_get_src_port(l->id));
    *out = l;
    return 0;
}

int smbd_linux_accept(struct listener *l, struct connection *c)
{
    c->channel = rdma_create_event_channel();
    if (!c->channel) return errno;
    int err = cm_event(l->channel, c->cancel_fd, RDMA_CM_EVENT_CONNECT_REQUEST, &c->id);
    if (err) return err;
    c->awaiting_accept = 1;
    // Move the acknowledged child before the accept loop polls the listener again.
    if (rdma_migrate_id(c->id, c->channel)) return errno;
    return 0;
}

int smbd_linux_finish_accept(struct connection *c)
{
    int err = prepare(c);
    if (err) return err;
    struct rdma_conn_param params = {.rnr_retry_count = 7};
    if (rdma_accept(c->id, &params)) return errno;
    c->awaiting_accept = 0;
    return established(c);
}

static int complete(struct connection *c, struct completion_queue *q, struct ibv_wc *wc)
{
    for (;;) {
        int n = ibv_poll_cq(q->cq, 1, wc);
        if (n < 0) return EIO;
        if (n == 1) return wc->status == IBV_WC_SUCCESS ? 0 : EIO;
        int err = wait_fd(q->channel->fd, c->cancel_fd, c->channel->fd);
        if (err) return err;
        struct ibv_cq *ready;
        void *context;
        if (ibv_get_cq_event(q->channel, &ready, &context)) return errno;
        ibv_ack_cq_events(ready, 1);
        if (ready != q->cq) return EIO;
        err = ibv_req_notify_cq(ready, 0);
        if (err) return err;
        // Poll again after arming: completions may arrive before or during rearm.
    }
}

int smbd_linux_send(struct connection *c, unsigned length)
{
    if (length > capacity) return EINVAL;
    struct ibv_sge sge = {.addr = (uintptr_t)(c->slots + (depth + 1) * capacity), .length = length, .lkey = c->mr->lkey};
    struct ibv_send_wr wr = {.opcode = IBV_WR_SEND, .send_flags = IBV_SEND_SIGNALED, .sg_list = &sge, .num_sge = 1};
    struct ibv_send_wr *bad;
    int err = ibv_post_send(c->id->qp, &wr, &bad);
    struct ibv_wc wc;
    return err ? err : complete(c, &c->tx, &wc);
}

int smbd_linux_receive(struct connection *c, unsigned *offset, unsigned *length)
{
    struct ibv_wc wc;
    int err = complete(c, &c->rx, &wc);
    if (err) return err;
    if (wc.opcode != IBV_WC_RECV || wc.wr_id > depth || wc.wr_id == c->spare || wc.byte_len > capacity) return EIO;
    err = post_receive(c, c->spare);
    if (err) return err;
    c->spare = (unsigned)wc.wr_id;
    *offset = c->spare * capacity;
    *length = wc.byte_len;
    return 0;
}
