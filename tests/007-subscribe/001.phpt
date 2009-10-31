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
Catchable fatal error: Argument 2 passed to Stomp::subscribe() must be an array, string given in %s on line %d
