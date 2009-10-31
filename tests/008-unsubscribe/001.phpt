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
Catchable fatal error: Argument 2 passed to Stomp::unsubscribe() must be an array, string given in %s on line %d
