--TEST--
Test stomp_connect() - Test error on CONNECT
--SKIPIF--
<?php
include "../skipif.inc"
?>
--FILE--
<?php 
try {
	$stomp = new Stomp('tcp://localhost', 'anotpresentusername1234');
} catch (Exception $e) {
	var_dump(get_class($e));
}
?>
--EXPECTF--
string(14) "StompException"
