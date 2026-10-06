<?php

mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');
mb_language('uni');
mb_regex_encoding('UTF-8');

setlocale(LC_ALL, 'fr_FR.utf8');
setlocale(LC_NUMERIC, 'C');
ini_set('date.timezone', 'Europe/Paris');

require __DIR__ . '/../vendor/autoload.php';

// Tests use short HMAC secrets on purpose: silence the one-time deprecation (see JWTTest "Short HMAC secrets")
(new ReflectionProperty(Pebble\Security\JWT::class, 'shortKeyWarned'))->setValue(null, true);
