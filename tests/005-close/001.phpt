--TEST--
Test stomp_close() - tests parameters
--SKIPIF--
<?php 
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php 
stomp_close(null);
?>
--EXPECTF--
Warning: stomp_close() expects parameter 1 to be resource, null given in %s on line %d
