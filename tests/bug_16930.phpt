--TEST--
Bug #16930 - readFrame reports error-frames as "timeout"
--SKIPIF--
<?php if (!extension_loaded("stomp")) print "skip"; ?>
--FILE--
<?php
$s = new Stomp();
$s->abort('t2');
try {
    var_dump($s->readFrame());
} catch(StompException $e) {
    var_dump($e->getMessage());
}

?>
--EXPECTF--
string(%d) "%s"
