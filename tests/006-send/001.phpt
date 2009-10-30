--TEST--
Check stomp_send
--SKIPIF--
<?php 
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect("tcp://localhost:61613")) print "skip";
?>
--FILE--
<?php 
$s = new Stomp('tcp://localhost:61613');
try {
    $s->send('', array());
} catch(StompException $e) {
    echo $e->getMessage();
}

$s->send('/queue/test', array());
?>
--EXPECTF--
Destination can not be empty
Fatal error: Stomp::send(): Expects parameter 2 to be a string or a StompFrame object. in %s on line %d
