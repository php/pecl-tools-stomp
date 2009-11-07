--TEST--
Test stomp_version()
--SKIPIF--
<?php if (!extension_loaded("stomp")) print "skip"; ?>
--FILE--
<?php 
echo stomp_version();
?>
--EXPECTF--
%d.%d.%d
