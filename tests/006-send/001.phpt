--TEST--
Test stomp_send() - tests parameters
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php 
include dirname(__DIR__) . "/skipif.inc";

$link = stomp_connect(STOMP_ADDRESS);

stomp_send($link, '', array());
stomp_send($link, '/queue/test-06', array());
var_dump(stomp_send($link, '/queue/test-06', ''));
var_dump(stomp_send($link, '/queue/test-06', 'A realMessage'));
var_dump(stomp_send($link, '/queue/test-06', 'بياريك شارون'));

?>
--EXPECTF--
Warning: stomp_send(): Destination can not be empty in %s on line %d

Warning: stomp_send(): Expects parameter %d to be a string or a StompFrame object. in %s on line %d
bool(true)
bool(true)
bool(true)
