// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC kernel implementation
 * (C) Copyright Red Hat Corp. 2021
 *
 * This file is part of the QUIC kernel implementation
 *
 * Initialization/cleanup for QUIC protocol support.
 *
 * Written or modified by:
 *    Xin Long <lucien.xin@gmail.com>
 */

#include <net/quic/quic.h>

static struct ctl_table quic_table[] = {
	{
		.procname	= "quic_mem",
		.data		= &sysctl_quic_mem,
		.maxlen		= sizeof(sysctl_quic_mem),
		.mode		= 0644,
		.proc_handler	= proc_doulongvec_minmax
	},
	{
		.procname	= "quic_rmem",
		.data		= &sysctl_quic_rmem,
		.maxlen		= sizeof(sysctl_quic_rmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "quic_wmem",
		.data		= &sysctl_quic_wmem,
		.maxlen		= sizeof(sysctl_quic_wmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ /* sentinel */ }
};

static struct ctl_table quic_net_table[] = {
	{
		.procname	= "max_udp_payload_size",
		.data		= &init_net.quic.max_udp_payload_size,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "initial_max_data",
		.data		= &init_net.quic.initial_max_data,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "initial_max_stream_data_bidi_local",
		.data		= &init_net.quic.initial_max_stream_data_bidi_local,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "initial_max_stream_data_bidi_remote",
		.data		= &init_net.quic.initial_max_stream_data_bidi_remote,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "initial_max_stream_data_uni",
		.data		= &init_net.quic.initial_max_stream_data_uni,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "initial_max_streams_bidi",
		.data		= &init_net.quic.initial_max_streams_bidi,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "initial_max_streams_uni",
		.data		= &init_net.quic.initial_max_streams_uni,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ /* sentinel */ }
};

int quic_sysctl_net_register(struct net *net)
{
	struct ctl_table *table;
	int i;

	table = kmemdup(quic_net_table, sizeof(quic_net_table), GFP_KERNEL);
	if (!table)
		return -ENOMEM;

	for (i = 0; table[i].data; i++)
		table[i].data += (char *)(&net->quic) - (char *)&init_net.quic;

	net->quic.sysctl_header = register_net_sysctl(net, "net/quic", table);
	if (!net->quic.sysctl_header) {
		kfree(table);
		return -ENOMEM;
	}
	return 0;
}

void quic_sysctl_net_unregister(struct net *net)
{
	struct ctl_table *table;

	table = net->quic.sysctl_header->ctl_table_arg;
	unregister_net_sysctl_table(net->quic.sysctl_header);
	kfree(table);
}

static struct ctl_table_header *quic_sysctl_header;

int quic_sysctl_register(void)
{
	quic_sysctl_header = register_net_sysctl(&init_net, "net/quic", quic_table);
	return quic_sysctl_header ? 0 : -ENOMEM;
}

void quic_sysctl_unregister(void)
{
	unregister_net_sysctl_table(quic_sysctl_header);
}
