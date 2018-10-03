--TEST--
Test stomp::send() - tests parameters
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php

include dirname(__DIR__) . "/config.inc";

$s = new Stomp(STOMP_ADDRESS);

$s->send('', array());
$s->send('/queue/test-06', array());
var_dump($s->send('/queue/test-06', ''));
var_dump($s->send('/queue/test-06', 'A realMessage'));
var_dump($s->send('/queue/test-06', 'بياريك شارون'));

?>
--EXPECTF--
Warning: Stomp::send(): Destination can not be empty in %s on line %d

Warning: Stomp::send(): Expects parameter %d to be a string or a StompFrame object. in %s on line %d
bool(true)
bool(true)
bool(true)
