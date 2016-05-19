--TEST--
Test Stomp::unsubscribe()
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php 
include dirname(__DIR__) . "/config.inc";

$s = new Stomp(STOMP_ADDRESS);

$s->unsubscribe('', array());
$s->unsubscribe('/queue/test', 'string');
?>
--EXPECTF--
Warning: Stomp::unsubscribe(): Destination can not be empty in %s on line %d

Catchable fatal error: Argument 2 passed to Stomp::unsubscribe() must be %s array, string given in %s on line %d
