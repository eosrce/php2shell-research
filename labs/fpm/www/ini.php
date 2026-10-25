<?php
header('Content-Type: text/plain');
foreach (['PHP_VERSION','memory_limit','post_max_size','display_errors',
          'session.save_path','session.upload_progress.enabled',
          'session.upload_progress.cleanup','max_input_vars'] as $k) {
    echo $k, '=', ini_get($k), "\n";
}
