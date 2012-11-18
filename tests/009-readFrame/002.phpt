--TEST--
Test stomp_read_frame() - test functionnality and parameters
--SKIPIF--
<?php
    if (!extension_loaded("stomp")) print "skip";
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php
$link = stomp_connect();
stomp_send($link, '/queue/test-09', 'A test Message');
stomp_subscribe($link, '/queue/test-09', array('ack' => 'auto'));
$result = stomp_read_frame($link);
var_dump($result['body']);
var_dump(stomp_read_frame($link));

?>
--EXPECTF--
string(14) "A test Message"
bool(false)
