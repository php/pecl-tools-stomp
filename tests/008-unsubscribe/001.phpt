--TEST--
Test Stomp::unsubscribe()
--SKIPIF--
<?php 
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php 
$s = new Stomp();
$s->unsubscribe('', array());
$s->unsubscribe('/queue/test', 'string');
?>
--EXPECTF--
Warning: Stomp::unsubscribe(): Destination can not be empty in %s on line %d

Catchable fatal error: Argument 2 passed to Stomp::unsubscribe() must be an array, string given in %s on line %d
