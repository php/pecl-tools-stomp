--TEST--
Test stomp::readFrame() - custom frame class 
--SKIPIF--
<?php
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php 

class customFrame extends stompFrame
{
    public function __construct($cmd, $headers, $body)
    {
        parent::__construct($cmd, $headers, $body);
    }
}

$s = new Stomp();
$s->send('/queue/test-09', 'A test Message');
$s->subscribe('/queue/test-09');
$frame = $s->readFrame('customFrame');
var_dump(get_class($frame), $frame->body);
?>
--EXPECT--
string(11) "customFrame"
string(14) "A test Message"
