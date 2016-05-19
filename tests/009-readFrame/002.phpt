--TEST--
Test stomp_read_frame() - test functionnality and parameters
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php
include dirname(__DIR__) . "/config.inc";

$link = stomp_connect(STOMP_ADDRESS);
stomp_send($link, '/queue/test-09', 'A test Message');
stomp_subscribe($link, '/queue/test-09', array('ack' => 'auto'));
$result = stomp_read_frame($link);
var_dump($result['body']);
var_dump(stomp_read_frame($link));

?>
--EXPECTF--
string(14) "A test Message"
bool(false)
