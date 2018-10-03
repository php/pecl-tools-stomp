--TEST--
Test stomp::readFrame() - tests functionnality and parameters
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php
include dirname(__DIR__) . "/config.inc";

$s = new Stomp(STOMP_ADDRESS);

$s->send('/queue/test-09', 'A test Message');
$s->subscribe('/queue/test-09', array('ack' => 'auto'));
var_dump($s->readFrame()->body);
var_dump($s->readFrame());

?>
--EXPECTF--
string(14) "A test Message"
bool(false)
