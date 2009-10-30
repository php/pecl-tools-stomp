--TEST--
Check stomp_version
--SKIPIF--
<?php if (!extension_loaded("stomp")) print "skip"; ?>
--FILE--
<?php 
echo stomp_version();
?>
--EXPECTREGEX--
[0-9]\.[0-9]\.[0-9]
