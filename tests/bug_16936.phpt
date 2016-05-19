--TEST--
Bug #16936 - Module segfaults on readFrame if Frame > STOMP_BUFSIZE
--SKIPIF--
<?php
$require_connection = true;
include __DIR__ . "/skipif.inc";
?>
--FILE--
<?php

include __DIR__ . "/config.inc";

$queue  = '/queue/foo';
$msg    = str_repeat('bar', 3000);

/* connection */
try {
    $stomp = new Stomp(STOMP_ADDRESS);
} catch(StompException $e) {
    die('Connection failed: ' . $e->getMessage());
}

/* send a message to the queue 'foo' */
$stomp->send($queue, $msg);

/* subscribe to messages from the queue 'foo' */
$stomp->subscribe($queue, array('ack' => 'auto'));

/* read a frame */
$frame = $stomp->readFrame();

if ($frame->body === $msg) {
    var_dump($frame->body);
    /* acknowledge that the frame was received */
    $stomp->ack($frame);
}

/* close connection */
unset($stomp);

?>
--EXPECTF--
string(%d) "%s"
