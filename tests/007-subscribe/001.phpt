--TEST--
Test Stomp::subscribe()
--SKIPIF--
<?php 
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php 
$s = new Stomp();
$s->subscribe('', array());
$s->subscribe('/queue/test', 'string');
?>
--EXPECTF--
Warning: Stomp::subscribe(): Destination can not be empty in %s on line %d

Catchable fatal error: Argument 2 passed to Stomp::subscribe() must be an array, string given in %s on line %d
