<?php /* p4w_sleep */
$id = preg_replace('/[^0-9]/', '', (string)($_GET["id"] ?? "0"));
file_put_contents('/tmp/p4w_marker_' . $id, getmypid() . "\n");
sleep((int)($_GET["t"] ?? 60));
echo "SLEEP";
