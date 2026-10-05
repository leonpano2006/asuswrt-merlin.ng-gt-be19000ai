/* Actual driver function bodies are injected by check-pcan-usb-fd.py. */
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t __le16;
typedef uint32_t __le32;
#define __packed __attribute__((packed))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
#define le16_to_cpu(x) le16toh(x)
#define le32_to_cpu(x) le32toh(x)
#define cpu_to_le16(x) htole16(x)
#define cpu_to_le32(x) htole32(x)
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define unlikely(x) (x)
#define GFP_KERNEL 0
#define GFP_ATOMIC 0
#define USB_SPEED_HIGH 3
#define PCAN_USB_MAX_CHANNEL 2
#define PCAN_USB_STATE_CONNECTED 1
#define CAN_CTRLMODE_FD_NON_ISO (1 << 7)
#define PCAN_USBPRO_EP_CMDOUT 1
#define PCAN_USBPRO_EP_CMDIN 0x81
#define PCAN_USBPRO_EP_MSGIN 0x82
#define PCAN_USBPRO_EP_MSGOUT_0 2
#define PCAN_USBPRO_EP_MSGOUT_1 3
#define PCAN_USBPRO_REQ_INFO 0
#define PCAN_USBPRO_INFO_FW 1
#define dev_info(...) ((void)0)
#define dev_err(...) ((void)0)
#define dev_warn(...) ((void)0)
#define netdev_err(...) ((void)0)

struct can_berr_counter { unsigned int txerr, rxerr; };
struct peak_time_ref { unsigned int unused; };
struct usb_device { unsigned int speed; };
struct net_device { struct { void *parent; } dev; };
struct peak_usb_adapter {
    const char *name;
    struct { u32 freq; } clock;
    unsigned int ctrl_count;
};
struct peak_usb_device {
    struct { u32 ctrlmode, ctrlmode_supported; } can;
    struct usb_device *udev;
    struct net_device *netdev;
    const struct peak_usb_adapter *adapter;
    struct peak_usb_device *prev_siblings;
    unsigned int ctrl_idx, state;
    u32 device_number;
    u8 ep_msg_in, ep_msg_out;
};
struct usb_host_interface { struct { u8 bInterfaceNumber; } desc; };
struct usb_interface { struct usb_host_interface altsetting[1]; };
struct urb { unsigned int pipe; int size; };
struct pucan_command { unsigned char data[8]; };

/* DRIVER_DECLARATIONS */

static struct pcan_ufd_fw_info firmware;
static int firmware_bytes, request_error, request_count;
static unsigned int bulk_pipe, bulk_calls, bulk_bytes, restart_pipe;
static void *kzalloc(size_t size, int flags) { return calloc(1, size); }
static void kfree(void *p) { free(p); }
static int pcan_usb_pro_send_req(struct peak_usb_device *dev, int req,
                                int value, void *data, int size)
{
    assert(req == PCAN_USBPRO_REQ_INFO && value == PCAN_USBPRO_INFO_FW);
    request_count++;
    if (request_error)
        return request_error;
    memset(data, 0, size);
    assert(firmware_bytes <= size);
    memcpy(data, &firmware, firmware_bytes);
    return 0;
}
static int pcan_usb_fd_drv_loaded(struct peak_usb_device *dev, int loaded) { return 0; }
static int pcan_usb_fd_set_clock_domain(struct peak_usb_device *dev, int clock) { return 0; }
static int pcan_usb_fd_set_can_led(struct peak_usb_device *dev, int led) { return 0; }
static unsigned int usb_sndbulkpipe(struct usb_device *dev, unsigned int ep) { return ep; }
static int usb_bulk_msg(struct usb_device *dev, unsigned int pipe, void *data,
                        int len, void *actual_length, int timeout)
{
    bulk_pipe = pipe;
    bulk_calls++;
    bulk_bytes += len;
    return 0;
}
static int pcan_usb_fd_build_restart_cmd(struct peak_usb_device *dev, u8 *buf)
{
    memset(buf, 0, 16);
    return 16;
}
static void pcan_usb_pro_restart_complete(struct urb *urb) { }
static void usb_fill_bulk_urb(struct urb *urb, struct usb_device *dev,
                             unsigned int pipe, u8 *data, int size,
                             void (*callback)(struct urb *), void *context)
{
    urb->pipe = pipe;
    urb->size = size;
}
static int usb_submit_urb(struct urb *urb, int flags)
{
    assert(urb->size == 24);
    restart_pipe = urb->pipe;
    return 0;
}

/* DRIVER_FUNCTIONS */

static void test_firmware(unsigned int type, unsigned int speed)
{
    struct peak_usb_adapter adapter = { .name = "PCAN-USB FD fixture",
        .clock.freq = 80000000, .ctrl_count = 2 };
    struct usb_device usb = { .speed = speed };
    struct net_device net = {0};
    struct pcan_usb_fd_device first = {0}, second = {0};
    struct urb urb = {0};
    u8 buf[512];
    const u8 cmd = type < 2 ? 1 : 4;
    const u8 tx0 = type < 2 ? 2 : 5;
    const u8 tx1 = type < 2 ? 3 : 6;
    const u8 rx = type < 2 ? 0x82 : 0x87;
    memset(&firmware, 0, sizeof(firmware));
    firmware.type = cpu_to_le16(type);
    firmware.size_of = cpu_to_le16(type < 2 ? 28 : 36);
    firmware.fw_version[0] = 3;
    firmware.cmd_out_ep = 4;
    firmware.cmd_in_ep = 0x84;
    firmware.data_out_ep[0] = 5;
    firmware.data_out_ep[1] = 6;
    firmware.data_in_ep = 0x87;
    firmware.dev_id[0] = cpu_to_le32(42);
    firmware.dev_id[1] = cpu_to_le32(43);
    firmware_bytes = type < 2 ? 28 : 36;
    request_error = 0;
    request_count = 0;
    first.dev.adapter = second.dev.adapter = &adapter;
    first.dev.udev = second.dev.udev = &usb;
    first.dev.netdev = second.dev.netdev = &net;
    first.dev.state = second.dev.state = PCAN_USB_STATE_CONNECTED;
    first.dev.ep_msg_in = second.dev.ep_msg_in = PCAN_USBPRO_EP_MSGIN;
    first.dev.ep_msg_out = PCAN_USBPRO_EP_MSGOUT_0;
    second.dev.ep_msg_out = PCAN_USBPRO_EP_MSGOUT_1;
    assert(pcan_usb_fd_init(&first.dev) == 0);
    assert(first.usb_if->fw_info.cmd_out_ep == cmd);
    assert(first.usb_if->fw_info.cmd_in_ep == (type < 2 ? 0x81 : 0x84));
    assert(first.dev.ep_msg_in == rx && first.dev.ep_msg_out == tx0);
    assert(first.dev.device_number == 42);
    assert(first.dev.can.ctrlmode_supported & CAN_CTRLMODE_FD_NON_ISO);
    second.dev.ctrl_idx = 1;
    second.dev.prev_siblings = &first.dev;
    assert(pcan_usb_fd_init(&second.dev) == 0);
    assert(request_count == 1);
    assert(second.usb_if == first.usb_if && second.cmd_buffer_addr == first.cmd_buffer_addr);
    assert(second.dev.ep_msg_in == rx && second.dev.ep_msg_out == tx1);
    assert(second.dev.device_number == 43);
    bulk_pipe = bulk_calls = bulk_bytes = restart_pipe = 0;
    memset(first.cmd_buffer_addr, 0, 128);
    assert(pcan_usb_fd_send_cmd(&first.dev, first.cmd_buffer_addr + 128) == 0);
    assert(bulk_pipe == cmd && bulk_bytes == 136);
    assert(bulk_calls == (speed == USB_SPEED_HIGH ? 1 : 3));
    assert(pcan_usb_fd_restart_async(&first.dev, &urb, buf) == 0);
    assert(restart_pipe == cmd);
    first.dev.state = 0;
    unsigned int previous_calls = bulk_calls;
    assert(pcan_usb_fd_send_cmd(&first.dev, first.cmd_buffer_addr + 8) == 0);
    assert(bulk_calls == previous_calls);
    free(first.cmd_buffer_addr);
    free(first.usb_if);
    printf("PASS firmware_type=%u speed=%u legacy_or_dynamic_endpoints second_channel sync_async_dispatch disconnected_no_send\n", type, speed);
}

int main(void)
{
    struct usb_interface interface = {0};
    assert(sizeof(struct pcan_ufd_fw_info) == 36);
    for (unsigned int n = 0; n < 3; n++) {
        interface.altsetting[0].desc.bInterfaceNumber = n;
        assert((pcan_usb_fd_probe(&interface) == 0) == (n == 0));
    }
    puts("PASS only_interface_zero_claimed");
    for (unsigned int type = 1; type <= 3; type++) {
        test_firmware(type, USB_SPEED_HIGH);
        test_firmware(type, 2);
    }
    puts("PCAN_USB_FD_DESCRIPTOR_FIXTURES_PASS");
    return 0;
}
