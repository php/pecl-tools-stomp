--TEST--
Check stom_connect
--SKIPIF--
<?php if (!extension_loaded("stomp")) print "skip"; ?>
--FILE--
<?php 
stomp_connect('');
stomp_connect(1);
stomp_connect('foo');
stomp_connect('foo://bar');
?>
--EXPECTF--
Warning: stomp_connect(): Invalid Broker URI in %s on line %d

Warning: stomp_connect(): Invalid Broker URI in %s on line %d

Warning: stomp_connect(): Invalid Broker URI in %s on line %d

Warning: stomp_connect(): Invalid Broker URI scheme in %s on line %d
