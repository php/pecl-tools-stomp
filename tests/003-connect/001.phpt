--TEST--
Test stomp_connect() - URI validation
--SKIPIF--
<?php if (!extension_loaded("stomp")) print "skip"; ?>
--FILE--
<?php
var_dump(stomp_connect(''), stomp_connect_error());
var_dump(stomp_connect(1), stomp_connect_error());
var_dump(stomp_connect('foo'), stomp_connect_error());
var_dump(stomp_connect('foo://bar'), stomp_connect_error());
?>
--EXPECT--
NULL
string(18) "Invalid Broker URI"
NULL
string(18) "Invalid Broker URI"
NULL
string(18) "Invalid Broker URI"
NULL
string(25) "Invalid Broker URI scheme"
