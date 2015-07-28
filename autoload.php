<?php
spl_autoload_register(function($class) {
    // does the class use the namespace prefix?
    $namespace = 'ParagonIE\\AntiCSRF\\';
    $base_dir = __DIR__.'/src/';

    $len = strlen($namespace);
    if (strncmp($namespace, $class, $len) !== 0) {
        // no, move to the next registered autoloader
        return;
    }

    // get the relative class name
    $relative_class = substr($class, $len);

    // replace the namespace prefix with the base directory, replace namespace
    // separators with directory separators in the relative class name, append
    // with .php
    $file = $base_dir . str_replace('\\', '/', $relative_class) . '.php';
    // if the file exists, require it
    if (file_exists($file)) {
        require $file;
    }
});
require_once __DIR__."/vendor/autoload.php";
