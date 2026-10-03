/* Compile-only kernel layout probe. Never linked or loaded as a module. */
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <linux/blk_types.h>
#include <linux/slub_def.h>

#define SIZE(name, type) const unsigned long abi_##name##_size = sizeof(type)
#define OFF(name, type, field) const unsigned long abi_##name = __builtin_offsetof(type, field)

SIZE(task, struct task_struct);
SIZE(sched_entity, struct sched_entity);
SIZE(page, struct page);
SIZE(mm, struct mm_struct);
SIZE(skb, struct sk_buff);
SIZE(netdev, struct net_device);
SIZE(sock, struct sock);
SIZE(bio, struct bio);
SIZE(kmem_cache, struct kmem_cache);
OFF(task_flags, struct task_struct, flags);
OFF(task_se, struct task_struct, se);
OFF(task_mm, struct task_struct, mm);
OFF(task_pid, struct task_struct, pid);
OFF(task_tgid, struct task_struct, tgid);
OFF(task_cred, struct task_struct, cred);
OFF(task_comm, struct task_struct, comm);
OFF(task_files, struct task_struct, files);
OFF(task_nsproxy, struct task_struct, nsproxy);
OFF(task_thread, struct task_struct, thread);
OFF(page_refcount, struct page, _refcount);
OFF(skb_data, struct sk_buff, data);
OFF(skb_head, struct sk_buff, head);
OFF(skb_dev, struct sk_buff, dev);
OFF(skb_protocol, struct sk_buff, protocol);
OFF(skb_truesize, struct sk_buff, truesize);
OFF(skb_users, struct sk_buff, users);
OFF(skb_bcm_ext, struct sk_buff, bcm_ext);
OFF(skb_pkt_type, struct sk_buff, __pkt_type_offset);
OFF(skb_transport_header, struct sk_buff, transport_header);
OFF(skb_network_header, struct sk_buff, network_header);
OFF(skb_bcm_ext_flags, struct sk_buff, bcm_ext.flags);
OFF(netdev_type, struct net_device, type);
OFF(netdev_tx_dropped, struct net_device, tx_dropped);
OFF(netdev_bcm_ext_iff_flags, struct net_device, bcm_nd_ext.iff_flags);
OFF(kmem_cache_random, struct kmem_cache, random);
OFF(kmem_cache_object_size, struct kmem_cache, object_size);
OFF(kmem_cache_alloc_size, struct kmem_cache, size);
OFF(sock_cgrp_data, struct sock, sk_cgrp_data);
OFF(sock_memcg, struct sock, sk_memcg);
OFF(sock_data_ready, struct sock, sk_data_ready);

#include <linux/sched/signal.h>
#include <linux/nsproxy.h>
/* Keep complete DWARF definitions, independent of compiler dead type removal. */
struct task_struct leon_task_probe;
struct sched_entity leon_sched_probe;
struct mm_struct leon_mm_probe;
struct page leon_page_probe;
struct sk_buff leon_skb_probe;
struct net_device leon_netdev_probe;
struct sock leon_sock_probe;
struct bio leon_bio_probe;
struct kmem_cache leon_slab_probe;
struct signal_struct leon_signal_probe;
struct nsproxy leon_nsproxy_probe;

