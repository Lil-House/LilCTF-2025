<?php
$orig = $_POST[0];
$ch = curl_init($orig);
curl_setopt($ch, CURLOPT_PROTOCOLS_STR, "all");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$data = curl_exec($ch);
echo curl_error($ch);
curl_close($ch);
