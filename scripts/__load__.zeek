##! An opinionated Zeek packet source for the cloud.

module PacketSource::UDP;

export {
	# Which receiver implementation to use. Can be one of RECVMMSG or IO_URING.
	const implementation: ReceiverImplementation = RECVMMSG &redef;

	# Whether to use the socket filedescriptor for kqueue.
	#
	# If F, the packet source acts in polling mode which can
	# be more efficient at high packet rates, but has a high
	# idle CPU usage due to the busy polling. See the poll_interval
	# setting below, too. Read up on Zeek's io_poll_interval_live
	# if you're considering tuning anything here.
	const recvmmsg_use_selectable_fd = T &redef;

	# Relax time for GetNextTimeout() when no packet was seen.
	#
	# Applies to the IO_URING implementation. Applies to the RECVMMSG
	# implementation only if recvmmsg_use_selectable_fd is F.
	const poll_interval: interval = 100usec &redef;

	# The size of the socket's UDP receive buffer to configure in bytes
	#
	# Set this value to ``0`` to use the kernel' default.
	const udp_recv_buffer_size = 16 * 1024 * 1024;
}
