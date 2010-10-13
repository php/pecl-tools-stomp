<?php
    if (!extension_loaded("stomp")) print "skip"; 
    if (!stomp_connect()) print "skip";
?>
