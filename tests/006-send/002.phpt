--TEST--
Test stomp::send() - tests parameters
--SKIPIF--
<?php
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php 
$s = new Stomp();

$s->send('', array());
$s->send('/queue/test-06', array());
var_dump($s->send('/queue/test-06', ''));
var_dump($s->send('/queue/test-06', 'A realMessage'));
var_dump($s->send('/queue/test-06', 'بياريك شارون'));
var_dump($s->send('بياريك شارون', 'بياريك شارون', array('receipt' => 'message-123')), $s->error());

?>
--EXPECTF--
Warning: Stomp::send(): Destination can not be empty in %s on line %d

Warning: Stomp::send(): Expects parameter %d to be a string or a StompFrame object. in %s on line %d
bool(true)
bool(true)
bool(true)
bool(false)
string(%d) "%s"
