<?php
include __DIR__ . "/config.inc";

if (!extension_loaded("stomp")) {
	print "skip"; 
}
if (isset($require_connection) && $require_connection) {
    $stomp = stomp_connect(STOMP_ADDRESS);
	if ($stomp === FALSE) {
		printf("skip cannot connect to server '%s'", stomp_connect_error());
		exit;
	}
}
?>
