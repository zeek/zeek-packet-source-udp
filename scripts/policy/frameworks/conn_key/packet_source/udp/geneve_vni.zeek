redef record conn_id_ctx += {
	geneve_vni: count &log &optional;
};

redef ConnKey::factory = ConnKey::CONNKEY_PACKETSOURCE_UDP_GENEVE_VNI_FIVETUPLE;
