--TEST--
Test stomp::readFrame() - Test the body binary safety
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php

include dirname(__DIR__) . "/config.inc";

$s = new Stomp(STOMP_ADDRESS);
$s->send('/queue/test-09', "A test Message\0Foo");
$s->subscribe('/queue/test-09', array('ack' => 'auto'));
var_dump($s->readFrame()->body);

?>
--EXPECTF--
string(18) "A test Message Foo"
