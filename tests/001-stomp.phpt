--TEST--
Check for stomp presence
--SKIPIF--
<?php if (!extension_loaded("stomp")) print "skip"; ?>
--FILE--
<?php
echo "stomp extension is available";
?>
--EXPECT--
stomp extension is available
