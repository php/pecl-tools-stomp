--TEST--
Check stomp
--SKIPIF--
<?php if (!extension_loaded("stomp")) print "skip"; ?>
--FILE--
<?php 

$queue = '/queue/test' . md5(uniqid());

if ($stomp = stomp_connect('tcp://localhost:61613')) {
    var_dump(stomp_send($stomp, $queue, 'test'));
    var_dump(stomp_subscribe($stomp, $queue));
    $msg = stomp_read_frame($stomp);
    echo $msg['command'] . '=>' . $msg['body'] . PHP_EOL;
    var_dump(stomp_ack($stomp, $msg['headers']['message-id']));
    var_dump(stomp_read_frame($stomp));
    var_dump(stomp_unsubscribe($stomp, $queue));
    var_dump(stomp_close($stomp));
}

echo PHP_EOL;

$stomp = new Stomp('tcp://localhost:61613');
try {
    var_dump($stomp->send($queue, 'test'));
    var_dump($stomp->subscribe($queue));
    $msg = $stomp->readFrame();
    echo $msg->command . '=>' . $msg->body . PHP_EOL;
    var_dump($stomp->ack($msg->headers['message-id']));
    var_dump($stomp->readFrame());
    var_dump($stomp->unsubscribe($queue));
    var_dump($stomp->disconnect());
} catch(StompException $e) {
}

?>
--EXPECT--
bool(true)
bool(true)
MESSAGE=>test
bool(true)
bool(false)
bool(true)
bool(true)

bool(true)
bool(true)
MESSAGE=>test
bool(true)
bool(false)
bool(true)
bool(true)
