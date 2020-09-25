--TEST--
Test stomp_close() - tests parameters
--SKIPIF--
<?php
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php
try {
	stomp_close(null);
} catch (TypeError $e) {
	echo $e->getMessage() . PHP_EOL;
}
?>
--EXPECTF--
%stomp_close()%s1%s null %s
