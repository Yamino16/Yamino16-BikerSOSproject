<?php
// Copiare in config.php e inserire i valori reali. config.php non va versionato.

define('DB_HOST', 'your-project.eu-central-1.aws.neon.tech');
define('DB_PORT', '5432');
define('DB_NAME', 'neondb');
define('DB_USER', '');
define('DB_PASS', '');

// Stringa casuale lunga, es. generata con: php -r "echo bin2hex(random_bytes(32));"
define('JWT_SECRET', '');

define('STRIPE_SECRET_KEY', '');
define('STRIPE_WEBHOOK_SECRET', '');

define('SMTP_HOST', 'smtp.ionos.it');
define('SMTP_PORT', 465);
define('SMTP_EMAIL', '');
define('SMTP_PASSWORD', '');

define('SITE_URL', 'https://bikersos.it');
