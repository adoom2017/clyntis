#ifndef CLYNTIS_H
#define CLYNTIS_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum { META_OK = 0, META_ERROR = 1, META_WOULD_BLOCK = 2, META_BUFFER_TOO_SMALL = 3 };
typedef uint64_t meta_handle;
typedef struct {
    uint32_t size;
    uint32_t version;
    void *context;
    int32_t (*protect_socket)(void *context, uint64_t socket);
    void (*packet_ready)(void *context);
} meta_hooks_v1;

/* Set size=sizeof(meta_hooks_v1), version=1. The size field is read before the
 * remaining fields; unsupported sizes are rejected. Hooks are optional except Android
 * requires protect_socket. A socket is borrowed, never close it. Return zero on
 * successful protection. Callbacks can run concurrently on worker threads and
 * must return promptly. Context must outlive stop/destroy. Callbacks may read
 * packets/snapshots, but must not call lifecycle functions. packet_ready signals
 * that the host can drain meta_read_packet_v1 until META_WOULD_BLOCK.
 *
 * Every handle owns its runtime. start is allowed once. stop/destroy join the
 * worker and all callbacks; neither can run inside a callback. Full configuration
 * changes use a newly created handle after stopping the previous one.
 *
 * No Rust buffer ownership crosses this API. All input bytes are copied/consumed
 * before return. Output is UTF-8 JSON/text or one raw IP packet, never NUL-terminated.
 * On META_BUFFER_TOO_SMALL, length reports required capacity and no bytes are
 * written; a queued packet remains available. Null output with zero capacity is
 * a size query. Output buffers and length fields must not overlap. Each function
 * returning META_ERROR records a thread-local error readable with meta_error_v1.
 * Handles are checked IDs: destroyed handles never become valid again.
 *
 * Packet calls require tun.enable=true. Hosts supply VPN permissions, system
 * routes/DNS and lifecycle. Packets have no Darwin address-family prefix.
 */
uint32_t meta_abi_version_v1(void);
int32_t meta_create_v1(const uint8_t *config, size_t length, const meta_hooks_v1 *hooks, meta_handle *out);
int32_t meta_start_v1(meta_handle handle);
int32_t meta_stop_v1(meta_handle handle);
int32_t meta_destroy_v1(meta_handle handle);
int32_t meta_close_connections_v1(meta_handle handle);
int32_t meta_network_changed_v1(meta_handle handle);
#ifdef __ANDROID__
/* Before start, duplicates a configured TUN fd. The host keeps its original fd.
 * Once set, meta_read/write_packet_v1 return META_ERROR; use fd packet I/O. */
int32_t meta_set_tun_fd_v1(meta_handle handle, int32_t fd);
#endif
int32_t meta_error_v1(uint8_t *buffer, size_t capacity, size_t *length);
int32_t meta_snapshot_v1(meta_handle handle, uint8_t *buffer, size_t capacity, size_t *length);
int32_t meta_update_v1(meta_handle handle, const uint8_t *json, size_t length);
int32_t meta_select_v1(meta_handle handle, const uint8_t *group, size_t group_length, const uint8_t *node, size_t node_length);
int32_t meta_write_packet_v1(meta_handle handle, const uint8_t *packet, size_t length);
int32_t meta_read_packet_v1(meta_handle handle, uint8_t *buffer, size_t capacity, size_t *length);
#ifdef __cplusplus
}
#endif
#endif
