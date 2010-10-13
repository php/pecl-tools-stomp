--TEST--
Test stomp_get_session_id()
--SKIPIF--
<?php 
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php 
$link = stomp_connect();
var_dump(stomp_get_session_id($link));
?>
--EXPECTF--
string(%d) "%s"
