--TEST--
Test stomp_close()
--SKIPIF--
<?php 
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php 
$link = stomp_connect();
if($link) echo "success" . PHP_EOL;
if(stomp_close($link)) echo "closed";
?>
--EXPECT--
success
closed
