--TEST--
Test Stomp::unsubscribe()
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php
include dirname(__DIR__) . "/config.inc";

$s = new Stomp(STOMP_ADDRESS);

$s->unsubscribe('', array());
$s->unsubscribe('/queue/test', 'string');
?>
--EXPECTF--
Warning: Stomp::unsubscribe(): Destination can not be empty in %s008-unsubscribe%c001.php on line %d

Fatal error: Uncaught TypeError: %s2%s string given in %s008-unsubscribe%c001.php:%d
Stack trace:
#0 %s(%d): Stomp->unsubscribe('/queue/test', 'string')
#1 {main}
  thrown in %s on line %d
