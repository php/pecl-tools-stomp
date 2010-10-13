--TEST--
Test Stomp::commit() - tests functionnality and parameters
--SKIPIF--
<?php
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php 
$s = new Stomp();

/* begin a transaction */
var_dump($s->begin('t1'));

// sends a message to the queue and specifies a good transaction
var_dump($s->send('/queue/test-011-commit', 'bar', array('transaction' => 't1')));

// sends a message to the queue and asks for a receipt
$s->send('/queue/test-011-commit', 'bar', array('transaction' => 't2', 'receipt' => 'tptp'));
echo gettype($s->error()) . PHP_EOL;

// commits a valid transaction
var_dump($s->commit('t1'));

// commits non valid transaction (null as a parameter) and asks for a receipt
var_dump($s->commit(null, array('receipt' => 'commit-key')));
var_dump($s->commit(null));

// commits a non valid transaction (a transaction id that does not exist) and asks for a receipt
$s->commit('t2', array('receipt' => 'commit-key'));
echo gettype($s->error());

unset($s);
?>
--EXPECTF--
bool(true)
bool(true)
string
bool(true)
bool(false)
bool(true)
string
