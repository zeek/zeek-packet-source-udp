redef record conn_id_ctx += {
	vxlan_vni: count &log &optional;
};

redef ConnKey::factory = ConnKey::CONNKEY_PACKETSOURCE_UDP_VXLAN_VNI_FIVETUPLE;
