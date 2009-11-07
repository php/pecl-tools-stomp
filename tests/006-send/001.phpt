--TEST--
Test stomp_send() - tests parameters
--SKIPIF--
<?php
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php 
$link = stomp_connect();

stomp_send($link, '', array());
stomp_send($link, '/queue/test-06', array());
var_dump(stomp_send($link, '/queue/test-06', ''));
var_dump(stomp_send($link, '/queue/test-06', 'A realMessage'));
var_dump(stomp_send($link, '/queue/test-06', 'بياريك شارون'));
var_dump(stomp_send($link, 'بياريك شارون', 'بياريك شارون', array('receipt' => 'message-123')), stomp_error($link));

?>
--EXPECTF--
Warning: stomp_send(): Destination can not be empty in %s on line %d

Warning: stomp_send(): Expects parameter %d to be a string or a StompFrame object. in %s on line %d
bool(true)
bool(true)
bool(true)
bool(false)
string(%d) "%s"
