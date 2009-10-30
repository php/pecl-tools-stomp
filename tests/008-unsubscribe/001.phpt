--TEST--
Check stomp_unsubscribe
--SKIPIF--
<?php 
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect("tcp://localhost:61613")) print "skip";
?>
--FILE--
<?php 
$s = new Stomp('tcp://localhost:61613');
try {
    $s->unsubscribe('', array());
} catch(StompException $e) {
    echo $e->getMessage();
}

$s->unsubscribe('/queue/test', 'string');
?>
--EXPECTF--
Destination can not be empty
Warning: Stomp::unsubscribe() expects parameter 2 to be array, string given in %s on line %d
