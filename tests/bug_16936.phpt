--TEST--
Bug #16936 - Module segfaults on readFrame if Frame > STOMP_BUFSIZE
--SKIPIF--
<?php if (!extension_loaded("stomp")) print "skip"; ?>
--FILE--
<?php

$queue  = '/queue/foo';
$msg    = str_repeat('bar', 3000);

/* connection */
try {
    $stomp = new Stomp();
} catch(StompException $e) {
    die('Connection failed: ' . $e->getMessage());
}

/* send a message to the queue 'foo' */
$stomp->send($queue, $msg);

/* subscribe to messages from the queue 'foo' */
$stomp->subscribe($queue);

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
