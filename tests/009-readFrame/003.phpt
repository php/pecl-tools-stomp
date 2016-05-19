--TEST--
Test stomp::readFrame() - custom frame class 
--SKIPIF--
<?php
$require_connection = true;
include dirname(__DIR__) . "/skipif.inc";
?>
--FILE--
<?php 

include dirname(__DIR__) . "/config.inc";

class customFrame extends stompFrame
{
    public function __construct($cmd, $headers, $body)
    {
        parent::__construct($cmd, $headers, $body);
    }
}

$s = new Stomp(STOMP_ADDRESS);
$s->send('/queue/test-09', 'A test Message');
$s->subscribe('/queue/test-09', array('ack' => 'auto'));
$frame = $s->readFrame('customFrame');
var_dump(get_class($frame), $frame->body);
?>
--EXPECT--
string(11) "customFrame"
string(14) "A test Message"
