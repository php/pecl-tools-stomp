--TEST--
Test stomp::readFrame() - test frame stack
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php 

include dirname(__DIR__) . "/config.inc";

$s = new Stomp(STOMP_ADDRESS);

var_dump($s->subscribe('/queue/test-buffer', array('ack' => 'auto')));
var_dump($s->send('/queue/test-buffer', "Message1", array('receipt' => 'msg-1')));
var_dump($s->send('/queue/test-buffer', "Message2", array('receipt' => 'msg-2')));
var_dump($s->send('/queue/test-buffer', "Message3", array('receipt' => 'msg-3')));
var_dump($s->readFrame()->body);
var_dump($s->readFrame()->body);
var_dump($s->readFrame()->body);
?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
bool(true)
string(8) "Message1"
string(8) "Message2"
string(8) "Message3"
