--TEST--
Bug #16930 - readFrame reports error-frames as "timeout"
--SKIPIF--
<?php
$require_connection = true;
include __DIR__ . "/skipif.inc";
?>
--FILE--
<?php

include  __DIR__ . "/config.inc";

$s = new Stomp(STOMP_ADDRESS);
$s->abort('t2');
try {
    var_dump($s->readFrame());
} catch(StompException $e) {
    var_dump($e->getMessage());
}

?>
--EXPECTF--
string(%d) "%s"
