--TEST--
Test Stomp::subscribe()
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php
include dirname(__DIR__) . "/skipif.inc";

$s = new Stomp(STOMP_ADDRESS);
$s->subscribe('', array());
$s->subscribe('/queue/test', 'string');
?>
--EXPECTF--
Warning: Stomp::subscribe(): Destination can not be empty in %s007-subscribe%c001.php on line %d

Fatal error: Uncaught TypeError: %s, string given in %s007-subscribe%c001.php:%d
Stack trace:
#0 %s001.php(%d): Stomp->subscribe('/queue/test', 'string')
#1 {main}
  thrown in %s007-subscribe%c001.php on line %d
