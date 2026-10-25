<?php
// Long-running page used to pin FPM children (multi-worker layouts).
// Usage: /pin.php?us=25000000  (microseconds; default 5 s)
usleep((int)($_GET['us'] ?? 5000000));
echo "pinned\n";
