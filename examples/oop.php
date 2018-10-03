<?php

$broker = 'tcp://localhost:61613';
$queue  = '/queue/foo';
$msg    = 'bar';

try {
    $stomp = new Stomp($broker);
    $stomp->send($queue, $msg);

    $stomp->subscribe($queue);
    $frame = $stomp->readFrame();
    if ($frame->body === $msg) {
        echo "Worked\n";
        $stomp->ack($frame, array('receipt' => 'message-12345'));
    } else {
        echo "Failed\n";
    }

    $stomp->disconnect();
} catch(StompException $e) {
    echo $e->getMessage();
}
