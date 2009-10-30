--TEST--
Check stomp_get_session_id 
--SKIPIF--
<?php 
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect("tcp://localhost:61613")) print "skip";
?>
--FILE--
<?php 
$s = stomp_connect("tcp://localhost:61613");
echo stomp_get_session_id($s);
?>
--EXPECTF--
%s
