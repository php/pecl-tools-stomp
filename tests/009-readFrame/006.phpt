--TEST--
Test stomp::readFrame() - test frame stack
--SKIPIF--
<?php
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php 
$s = new Stomp();
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
