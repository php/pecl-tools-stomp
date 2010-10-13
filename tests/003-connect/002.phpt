--TEST--
Test stomp_connect() - Test connection 
--SKIPIF--
<?php if (!extension_loaded("stomp")) print "skip"; ?>
--FILE--
<?php 
var_dump(stomp_connect());
var_dump(stomp_connect_error());
?>
--EXPECTF--
resource(%d) of type (stomp connection)
NULL
