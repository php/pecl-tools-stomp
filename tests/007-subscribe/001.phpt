--TEST--
Test Stomp::subscribe()
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php 
include dirname(__DIR__) . "/skipif.inc";

$s = new Stomp(STOMP_ADDRESS);
$s->subscribe('', array());
$s->subscribe('/queue/test', 'string');
?>
--EXPECTF--
Warning: Stomp::subscribe(): Destination can not be empty in %s on line %d

Catchable fatal error: Argument 2 passed to Stomp::subscribe() must be %s array, string given in %s on line %d
