--TEST--
Test stomp::send() - test send with receipt
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php
include dirname(__DIR__) . "/skipif.inc";
$s = new Stomp(STOMP_ADDRESS);
var_dump($s->send('/queue/test-06', 'A real message', array('receipt' => 'message-12345')));
?>
--EXPECTF--
bool(true)
