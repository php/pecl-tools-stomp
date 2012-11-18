--TEST--
Test stomp::readFrame() - tests functionnality and parameters
--SKIPIF--
<?php
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php 
$s = new Stomp();
$s->send('/queue/test-09', 'A test Message');
$s->subscribe('/queue/test-09', array('ack' => 'auto'));
var_dump($s->readFrame()->body);
var_dump($s->readFrame());

?>
--EXPECTF--
string(14) "A test Message"
bool(false)
