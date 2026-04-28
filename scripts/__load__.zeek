##! An opinionated Zeek packet source for the cloud.

module PacketSource::UDP;

export {
	## Which receiver implementation to use for the UDP receiver.
	## Can be one of PacketSource::UDP::RECVMMSG or
	## PacketSource::UDP::IO_URING.
	const implementation: ReceiverImplementation = RECVMMSG &redef;

	## Relax time for GetNextTimeout() when no packet was seen.
	##
	## Applies to the IO_URING implementation. Applies to the RECVMMSG
	## implementation only if recvmmsg_use_selectable_fd is F.
	const poll_interval: interval = 100usec &redef;

	## The size of the socket's UDP receive buffer to configure in bytes
	##
	## Set this value to ``0`` to use the kernel default.
	const udp_recv_buffer_size = 16 * 1024 * 1024 &redef;

	## Whether to use select on the listening UDP socket to wake up Zeek's IO loop.
	##
	## This applies to the recvmmsg() implementation only.
	##
	## If F, the packet source acts in polling mode which can
	## be more efficient at high packet rates. However, this comes
	## with a higher idle CPU usage due to the busy polling. See the
	## poll_interval setting above, too. Read up on Zeek's
	## io_poll_interval_live variable if you're considering tuning anything here.
	const recvmmsg_use_selectable_fd = T &redef;

	## The number of mmsghdrs to pass to recvmmsg() at once.
	const recvmmsg_buffers = 1024 &redef;

	## The size of an individual packet buffer for the recvmmsg() implementation.
	##
	## This is used for the iov_len field of an individual struct iovec.
	## Defaults to 9216 + 32 bytes to cover jumbo packets and a bit of
	## wiggle room for any extra encapsulation.
	const recvmmsg_buffer_size = 9216 + 32 &redef;

	## The number of entries in the submission queue. We only
	## submit a single multishot RECVMSG op at a time, so keep
	## this pretty small.
	const io_uring_sq_entries = 2 &redef;

	## The number of entries in the completion queue. Used with
	## io_uring_queue_init_params()
	const io_uring_cq_entries = 256 &redef;

	## The number of buffers for the ring.
	const io_uring_buffers = 1024 &redef;

	## Shift value for the buffer size. Default is 14, meaning
	## a buffer size of (1 << 14) = 16KB. This covers jumbo packets and
	## also has plenty of room for the SO_TIMESTAMP information as well.
	const io_uring_buffer_shift = 14 &redef;
}
