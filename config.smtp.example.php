<?php
/**
 * SMTP configuration template.
 * Copy this file to config.smtp.php and fill in the real credentials.
 * config.smtp.php must NEVER be committed (see .gitignore).
 */
define('SMTP_HOST', 'mail.somostributa.com');          // TODO: confirm the real mail host
define('SMTP_PORT', 465);
define('SMTP_USER', 'reclamaciones@somostributa.com');
define('SMTP_PASS', 'TU_CONTRASEÑA_AQUI');
define('SMTP_FROM_NAME', 'Tributa');

define('EMPRESA_NOTIF_EMAIL', 'reclamaciones@somostributa.com');

// hCaptcha (https://dashboard.hcaptcha.com)
define('HCAPTCHA_SITE_KEY',   'TU_SITE_KEY_AQUI');
define('HCAPTCHA_SECRET_KEY', 'TU_SECRET_KEY_AQUI');

// ── Seguridad y anti-spam (opcionales; estos son los valores por defecto) ──────
// Verificación TLS del servidor SMTP. Déjalo en true; cámbialo a false SOLO si el
// certificado del correo no coincide con SMTP_HOST y el envío falla.
define('SMTP_VERIFY_TLS', true);

// Sal para el hash SHA-256 de las IP (límites de envío y logs). Pon una cadena larga y
// aleatoria. Si la dejas vacía, se genera una sal por instalación en reclamaciones/.ip_salt
define('IP_HASH_SALT', '');

// Límites por IP (hash): mínimo de segundos entre envíos y máximo de envíos por 24 horas.
define('RATE_LIMIT_IP_INTERVAL', 1800);   // 1 envío cada 30 minutos
define('RATE_LIMIT_IP_DAILY',    5);      // máximo 5 envíos por día

// Límites globales del sitio (evitan spam distribuido e inundación del buzón).
define('RATE_LIMIT_SITE_HOURLY', 20);     // máximo 20 envíos por hora
define('RATE_LIMIT_SITE_DAILY',  80);     // máximo 80 envíos por día
