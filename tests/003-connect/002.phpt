--TEST--
Test stomp_connect() - Test connection 
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__). "/skipif.inc";
?>
--FILE--
<?php 
include dirname(__DIR__) . "/config.inc";
var_dump(stomp_connect(STOMP_ADDRESS));
var_dump(stomp_connect_error());
?>
--EXPECTF--
resource(%d) of type (stomp connection)
NULL
