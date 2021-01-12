--TEST--
Test Stomp::getReadTimout() and Stomp::setReadTimeout() - tests functionnality and parameters
--INI--
stomp.default_read_timeout_sec=5
stomp.default_read_timeout_usec=5
--SKIPIF--
<?php
    if (!extension_loaded("stomp")) print "skip";
    if (!stomp_connect()) print "skip";
?>
--FILE--
<?php
$s = new Stomp();

// First test, read from ini variables,  expected to return 5.5
var_dump($s->getReadTimeout());

// Set read timout with an integer as seconds
var_dump($s->setReadTimeout(10));
// Second test, read supposed to return 10.0
var_dump($s->getReadTimeout());

// Set read timout with an integer as seconds
var_dump($s->setReadTimeout(10, 5));
// Third test, read supposed to return 10.5
var_dump($s->getReadTimeout());

try {
	// Set read timout with the first param as a string, supposed to trigger a warning/exception
	var_dump($s->setReadTimeout(''));
} catch (TypeError $e) {
	echo $e->getMessage() . PHP_EOL;
}
// Fourth test, read supposed to get the last value set : 10.5
var_dump($s->getReadTimeout());

try {
	// Set read timout with the second param as a string, supposed to trigger a warning/exception
	var_dump($s->setReadTimeout(10, ''));
} catch (TypeError $e) {
	echo $e->getMessage() . PHP_EOL;
}
// Fourth test, read supposed to get the last value set : 10.5
var_dump($s->getReadTimeout());

// Set read timout with the params as null
var_dump($s->setReadTimeout(null, null));
// Fifth test, read supposed to get the last value set : 0.0
var_dump($s->getReadTimeout());


unset($s);
?>
--EXPECTF--
array(2) {
  ["sec"]=>
  int(5)
  ["usec"]=>
  int(5)
}
NULL
array(2) {
  ["sec"]=>
  int(10)
  ["usec"]=>
  int(0)
}
NULL
array(2) {
  ["sec"]=>
  int(10)
  ["usec"]=>
  int(5)
}
%AStomp::setReadTimeout()%s1%s string given%A
array(2) {
  ["sec"]=>
  int(10)
  ["usec"]=>
  int(5)
}
%AStomp::setReadTimeout()%s2%s string given%A
array(2) {
  ["sec"]=>
  int(10)
  ["usec"]=>
  int(5)
}
NULL
array(2) {
  ["sec"]=>
  int(0)
  ["usec"]=>
  int(0)
}
