--TEST--
Check stomp_subscribe
--SKIPIF--
<?php 
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect("tcp://localhost:61613")) print "skip";
?>
--FILE--
<?php 
$s = new Stomp('tcp://localhost:61613');
try {
    $s->subscribe('', array());
} catch(StompException $e) {
    echo $e->getMessage();
}

$s->subscribe('/queue/test', 'string');
?>
--EXPECTF--
Destination can not be empty
Warning: Stomp::subscribe() expects parameter 2 to be array, string given in %s on line %d
