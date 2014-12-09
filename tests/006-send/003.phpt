--TEST--
Test stomp::send() - test send with receipt
--SKIPIF--
<?php
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php 
$s = new Stomp();
var_dump($s->send('/queue/test-06', 'A real message', array('receipt' => 'message-12345')));
?>
--EXPECTF--
bool(true)
