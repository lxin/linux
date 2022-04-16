/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NETNS_QUIC_H__
#define __NETNS_QUIC_H__

struct netns_quic {
#ifdef CONFIG_SYSCTL
	struct ctl_table_header *sysctl_header;
#endif
	u32 max_udp_payload_size;
	u32 initial_max_data;
	u32 initial_max_stream_data_bidi_local;
	u32 initial_max_stream_data_bidi_remote;
	u32 initial_max_stream_data_uni;
	u32 initial_max_streams_bidi;
	u32 initial_max_streams_uni;
};

#endif /* __NETNS_QUIC_H__ */
