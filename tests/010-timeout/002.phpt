--TEST--
Test stomp_get_read_timout() and stomp_set_read_timeout() - tests functionnality and parameters
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
$link = stomp_connect();

// First test, read from ini variables, expected to return 5.5
var_dump(stomp_get_read_timeout($link));

// Set read timout with an integer as seconds
var_dump(stomp_set_read_timeout($link, 10));
// Second test, read supposed to return 10.0
var_dump(stomp_get_read_timeout($link));

// Set read timout with an integer as seconds
var_dump(stomp_set_read_timeout($link, 10, 5));
// Third test, read supposed to return 10.5
var_dump(stomp_get_read_timeout($link));

try {
	// Set read timout with the first param as a string, supposed to trigger a warning on PHP 7
	// supposed to trigger an exception on PHP 8
	var_dump(stomp_set_read_timeout($link, ''));
} catch (TypeError $e) {
	echo $e->getMessage() . PHP_EOL;
}
// Fourth test, read supposed to get the last value set : 10.5
var_dump(stomp_get_read_timeout($link));

try {
	// Set read timout with the second param as a string, supposed to trigger a warning on PHP 7
	// supposed to trigger an exception on PHP 8
	var_dump(stomp_set_read_timeout($link, 10, ''));
} catch (TypeError $e) {
	echo $e->getMessage() . PHP_EOL;
}
// Fourth test, read supposed to get the last value set : 10.5
var_dump(stomp_get_read_timeout($link));

// Set read timout with the params as null
var_dump(stomp_set_read_timeout($link, null, null));
// Fifth test, read supposed to get the last value set : 0.0
var_dump(stomp_get_read_timeout($link));


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
%Astomp_set_read_timeout()%s2%S string given%A
array(2) {
  ["sec"]=>
  int(10)
  ["usec"]=>
  int(5)
}
%Astomp_set_read_timeout()%s3%s string given%A
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
