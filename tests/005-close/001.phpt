--TEST--
Check stomp_close
--SKIPIF--
<?php 
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect("tcp://localhost:61613")) print "skip";
?>
--FILE--
<?php 
$s = stomp_connect("tcp://localhost:61613");
if(stomp_close($s)) echo "close";
?>
--EXPECT--
close
