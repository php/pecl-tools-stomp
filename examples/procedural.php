<?php

$broker = 'tcp://localhost:61613';
$queue  = '/queue/foo';
$msg    = 'bar';

if($stomp = stomp_connect($broker)) {

    stomp_begin($stomp, 't1');
    stomp_send($stomp, $queue, $msg, array('transaction' => 't1'));
    stomp_commit($stomp, 't1');

    stomp_subscribe($stomp, $queue);
    $frame = stomp_read_frame($stomp);
    if ($frame['body'] === $msg) {
        echo "Worked\n";
        stomp_ack($stomp, $frame['headers']['message-id']);
    } else {
        echo "Failed\n";
    }

    stomp_close($stomp);
}

