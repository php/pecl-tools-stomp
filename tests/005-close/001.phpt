--TEST--
Test stomp_close() - tests parameters
--SKIPIF--
<?php 
    if (!extension_loaded("stomp")) print "skip"; 
?>
--FILE--
<?php 
stomp_close(null);
?>
--EXPECTF--
Warning: stomp_close() expects parameter 1 to be resource, null given in %s on line %d
