--TEST--
Test stomp_get_session_id()
--SKIPIF--
<?php 
$require_connection = true;
include dirname(__DIR__) . '/skipif.inc';
?>
--FILE--
<?php 
include dirname(__DIR__) . "/config.inc";
$link = stomp_connect(STOMP_ADDRESS);
var_dump(stomp_get_session_id($link));
?>
--EXPECTF--
string(%d) "%s"
