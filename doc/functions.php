<?php

/**
 * Get the current version of the stomp extension
 * 
 * @return string version
 */
function stomp_version() {
}

/**
 * Connect to server
 * 
 * @param string $broker broker URI
 * @param string $username The username
 * @param string $password The password
 * @param array $headers additional headers (example: receipt).
 * @return Ressource stomp connection identifier on success, or FALSE on failure 
 */
function stomp_connect($broker = null, $username = null, $password = null, array $headers = array()) {
}

/**
 * Get the current stomp session ID
 * 
 * @param ressource $link identifier returned by stomp_connect
 * @return string stomp session ID if it exists, or FALSE otherwise
 */
function stomp_get_session_id($link) {
}

/**
 * Close stomp connection
 *
 * @param ressource $link identifier returned by stomp_connect
 * @return boolean TRUE on success, or FALSE on failure 
 */
function stomp_close($link) {
}

/** 
 * Sends a message to a destination in the messaging system
 * 
 * @param ressource $link identifier returned by stomp_connect
 * @param string $destination indicates where to send the message 
 * @param string|StompFrame $msg message to be sent
 * @param array $headers additional headers (example: receipt).
 * @return boolean TRUE on success, or FALSE on failure 
 */
function stomp_send($link, $destination, $msg, array $headers = array()) {
}

/**
 * Register to listen to a given destination
 * 
 * @param ressource $link identifier returned by stomp_connect
 * @param string $destination indicates which destination to subscribe to 
 * @param array $headers additional headers (example: receipt).
 * @return boolean TRUE on success, or FALSE on failure 
 */
function stomp_subscribe($link, $destination, array $headers = array()) {
}

/**
 * Remove an existing subscription
 *
 * @param ressource $link identifier returned by stomp_connect
 * @param string $destination indicates which subscription to remove
 * @param array $headers additional headers (example: receipt).
 * @return boolean TRUE on success, or FALSE on failure 
 */
function stomp_unsubscribe($link, $destination, array $headers = array()) {
}

/**
 * Indicate whether or not there is a frame ready to read
 * 
 * @param ressource $link identifier returned by stomp_connect
 * @return boolean TRUE if there is one, or FALSE otherwise
 */
function stomp_has_frame($link) {
}

/**
 * Read the next frame
 *
 * @param ressource $link identifier returned by stomp_connect
 * @return array on success, or FALSE on failure
 */
function stomp_read_frame($link) {
}

/**
 * Start a transaction
 *
 * @param ressource $link identifier returned by stomp_connect
 * @param string $transaction_id transaction id
 * @return boolean TRUE on success, or FALSE on failure 
 */
function stomp_begin($link, $transaction_id) {
}

/**
 * Commit a transaction in progress
 *
 * @param ressource $link identifier returned by stomp_connect
 * @param string $transaction_id transaction id
 * @return boolean TRUE on success, or FALSE on failure 
 */
function stomp_commit($link, $transaction_id) { 
}

/**
 * Roll back a transaction in progress
 *
 * @param ressource $link identifier returned by stomp_connect
 * @param string $transaction_id transaction id
 * @return boolean TRUE on success, or FALSE on failure 
 */
function stomp_abort($link, $transaction_id) {
}

/**
 * Acknowledge consumption of a message from a subscription using client acknowledgment
 * 
 * @param ressource $link identifier returned by stomp_connect
 * @param string|StompFrame $msg message/messageId to be acknowledged
 * @param array $headers additional headers (example: receipt).
 * @return boolean TRUE on success, or FALSE on failure 
 */
function stomp_ack($link, $msg, array $headers = array()) {
}

/**
 * Get the last stomp error
 *
 * @param ressource $link identifier returned by stomp_connect
 * @return string Error message, or FALSE if no error
 */
function stomp_error($link) {
}

/**
 * Set timeout
 * 
 * @param ressource $link identifier returned by stomp_connect
 * @param int $seconds the seconds part of the timeout to be set
 * @param int $microseconds the microseconds part of the timeout to be set
 * @return void
 */
function stomp_set_timeout($link, $seconds, $microseconds = 0) {
}

/**
 * Get timeout
 * 
 * @param ressource $link identifier returned by stomp_connect
 * @return array Array with timeout informations
 */
function stomp_get_timeout($link) {
}
