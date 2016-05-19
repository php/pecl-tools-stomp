--TEST--
Test stomp_close()
--SKIPIF--
<?php 
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php 
include dirname(__DIR__) . "/config.inc";
$link = stomp_connect(STOMP_ADDRESS);
if($link) echo "success" . PHP_EOL;
if(stomp_close($link)) echo "closed";
?>
--EXPECT--
success
closed
