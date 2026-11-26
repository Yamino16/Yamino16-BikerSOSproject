<?php
require __DIR__ . '/config.php';

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, Stripe-Signature');
header('Content-Type: application/json; charset=UTF-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

const TOKEN_TTL = 86400;
const RESET_TOKEN_TTL = 900;
const STRIPE_SIGNATURE_TOLERANCE = 300;

// Campi del profilo esposti dalla pagina pubblica di emergenza.
const EMERGENCY_FIELDS = 'name, dob, photo_url, blood_type, ice_name, ice_phone, allergies, conditions, medications';

function respond(int $status, $data): void
{
    http_response_code($status);
    echo json_encode($data);
    exit;
}

// Invia subito la risposta al client e lascia proseguire lo script (es. invio email).
function respondAndContinue(int $status, $data): void
{
    $output = json_encode($data);
    ignore_user_abort(true);
    http_response_code($status);
    header('Connection: close');
    header('Content-Length: ' . strlen($output));
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    echo $output;
    flush();
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    }
}

function getDB(): PDO
{
    $dsn = sprintf('pgsql:host=%s port=%s dbname=%s sslmode=require', DB_HOST, DB_PORT, DB_NAME);
    try {
        $db = new PDO($dsn, DB_USER, DB_PASS);
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $db;
    } catch (PDOException $e) {
        error_log('Connessione DB fallita: ' . $e->getMessage());
        respond(500, ['error' => 'Database non raggiungibile']);
    }
}

// --- Token -------------------------------------------------------------
// Formato compatibile con i token già emessi: la firma HMAC è calcolata sulle
// parti in base64 standard, poi l'intero token viene convertito in base64url.

function toBase64Url(string $value): string
{
    return str_replace(['+', '/', '='], ['-', '_', ''], $value);
}

function fromBase64Url(string $value): string
{
    $value = strtr($value, '-_', '+/');
    return $value . str_repeat('=', (4 - strlen($value) % 4) % 4);
}

function sign(string $header, string $payload): string
{
    return base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));
}

function issueToken(array $claims): string
{
    $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload = base64_encode(json_encode($claims));
    return toBase64Url("$header.$payload." . sign($header, $payload));
}

function verifyToken(string $token, ?string $action = null): ?array
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return null;
    }
    [$header, $payload, $signature] = $parts;
    $header = fromBase64Url($header);
    $payload = fromBase64Url($payload);

    if (!hash_equals(toBase64Url(sign($header, $payload)), $signature)) {
        return null;
    }

    $claims = json_decode(base64_decode($payload), true);
    if (!is_array($claims) || !isset($claims['id'], $claims['exp']) || $claims['exp'] < time()) {
        return null;
    }
    if (($claims['action'] ?? null) !== $action) {
        return null;
    }
    return $claims;
}

function authenticate(): array
{
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';
    if (!preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
        respond(401, ['error' => 'Token mancante']);
    }
    $claims = verifyToken($matches[1]);
    if ($claims === null) {
        respond(403, ['error' => 'Token non valido o scaduto']);
    }
    return $claims;
}

function uuidV4(): string
{
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
}

function isValidEmail(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

// --- Email -------------------------------------------------------------

function renderEmail(string $title, string $messageHtml, string $buttonText, string $buttonUrl): string
{
    $button = '';
    if ($buttonText && $buttonUrl) {
        $button = '<div style="text-align: center;">
                    <a href="' . $buttonUrl . '" style="display: inline-block; background-color: #FF1E1E; color: #ffffff; text-decoration: none; padding: 16px 36px; border-radius: 12px; font-weight: 800; font-size: 14px; letter-spacing: 1.5px; text-transform: uppercase;">' . $buttonText . '</a>
                  </div>';
    }

    return '<!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="margin: 0; padding: 40px 20px; background-color: #050505; font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, Helvetica, Arial, sans-serif;">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: 0 auto; background-color: #0a0a0a; border: 1px solid #1a1a1a; border-radius: 16px; overflow: hidden;">
            <tr>
                <td style="padding: 40px; text-align: center; border-bottom: 1px solid #1a1a1a; background: linear-gradient(180deg, #111111 0%, #0a0a0a 100%);">
                    <h1 style="color: #ffffff; margin: 0; font-size: 32px; font-weight: 900; font-style: italic; letter-spacing: -1px;">Biker<span style="color: #FF1E1E;">SOS</span></h1>
                </td>
            </tr>
            <tr>
                <td style="padding: 40px;">
                    <h2 style="color: #ffffff; margin: 0 0 20px 0; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">' . $title . '</h2>
                    <div style="color: #a1a1aa; font-size: 15px; line-height: 1.6; margin-bottom: 35px;">' . $messageHtml . '</div>
                    ' . $button . '
                </td>
            </tr>
            <tr>
                <td style="padding: 30px; text-align: center; background-color: #050505; border-top: 1px solid #1a1a1a;">
                    <p style="color: #3f3f46; font-size: 11px; margin: 0;">&copy; ' . date('Y') . ' BikerSOS. Questo è un messaggio automatico, non rispondere.</p>
                </td>
            </tr>
        </table>
    </body>
    </html>';
}

// Invio SMTP diretto (SSL, AUTH LOGIN): l'hosting non mette a disposizione mail() autenticato.
function sendEmail(string $to, string $subject, string $title, string $messageHtml, string $buttonText = '', string $buttonUrl = ''): void
{
    if (!isValidEmail($to)) {
        return;
    }
    $html = renderEmail($title, $messageHtml, $buttonText, $buttonUrl);

    $socket = @fsockopen('ssl://' . SMTP_HOST, SMTP_PORT, $errno, $errstr, 15);
    if (!$socket) {
        error_log("SMTP non raggiungibile: $errstr ($errno)");
        return;
    }

    $send = function (string $line) use ($socket) {
        fputs($socket, $line . "\r\n");
        fgets($socket, 515);
    };

    fgets($socket, 515);
    $send('EHLO ' . $_SERVER['SERVER_NAME']);
    $send('AUTH LOGIN');
    $send(base64_encode(SMTP_EMAIL));
    $send(base64_encode(SMTP_PASSWORD));
    $send('MAIL FROM: <' . SMTP_EMAIL . '>');
    $send('RCPT TO: <' . $to . '>');
    $send('DATA');

    $headers = 'From: BikerSOS <' . SMTP_EMAIL . ">\r\n" .
               "To: <$to>\r\n" .
               "Subject: $subject\r\n" .
               "MIME-Version: 1.0\r\n" .
               "Content-Type: text/html; charset=UTF-8\r\n" .
               "Content-Transfer-Encoding: 8bit\r\n\r\n";
    $send($headers . $html . "\r\n.");
    fputs($socket, "QUIT\r\n");
    fclose($socket);
}

// --- Stripe ------------------------------------------------------------

function isValidStripeSignature(string $payload, string $header): bool
{
    $timestamp = '';
    $signatures = [];
    foreach (explode(',', $header) as $item) {
        $pair = explode('=', $item, 2);
        if (count($pair) !== 2) {
            continue;
        }
        if ($pair[0] === 't') {
            $timestamp = $pair[1];
        } elseif ($pair[0] === 'v1') {
            $signatures[] = $pair[1];
        }
    }

    if ($timestamp === '' || abs(time() - (int) $timestamp) > STRIPE_SIGNATURE_TOLERANCE) {
        return false;
    }

    $expected = hash_hmac('sha256', "$timestamp.$payload", STRIPE_WEBHOOK_SECRET);
    foreach ($signatures as $signature) {
        if (hash_equals($expected, $signature)) {
            return true;
        }
    }
    return false;
}

function saveOrder(array $session): void
{
    $customerEmail = $session['customer_details']['email'] ?? 'N/D';
    $total = $session['amount_total'];
    $shipping = $session['shipping_details'] ?? $session['customer_details'] ?? null;
    $name = $session['shipping_details']['name'] ?? $session['customer_details']['name'] ?? 'N/D';
    $address = $shipping['address']['line1'] ?? 'N/D';
    $city = $shipping['address']['city'] ?? 'N/D';
    $postalCode = $shipping['address']['postal_code'] ?? 'N/D';
    $country = $shipping['address']['country'] ?? 'N/D';

    try {
        $db = getDB();
        $stmt = $db->prepare('INSERT INTO orders (user_id, stripe_session_id, customer_email, shipping_name, shipping_address, shipping_city, shipping_postal_code, shipping_country, amount_total) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
        $stmt->execute([$session['client_reference_id'] ?? null, $session['id'], $customerEmail, $name, $address, $city, $postalCode, $country, $total]);
    } catch (Exception $e) {
        error_log('Salvataggio ordine fallito: ' . $e->getMessage());
        return;
    }

    if ($customerEmail === 'N/D') {
        return;
    }

    $e = fn($value) => htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
    $price = number_format($total / 100, 2, ',', '.');
    $orderHtml = "
        Abbiamo ricevuto il tuo ordine e stiamo configurando il tuo hardware ufficiale.<br><br>
        <div style='background-color: #111111; border: 1px solid #222222; border-radius: 12px; padding: 20px; margin-top: 20px; text-align: left;'>
            <p style='color: #52525b; font-size: 11px; text-transform: uppercase; font-weight: 800; letter-spacing: 1px; margin: 0 0 5px 0;'>Totale Pagato</p>
            <p style='color: #ffffff; font-size: 28px; font-weight: 900; margin: 0 0 20px 0;'>&euro;{$price}</p>
            <p style='color: #52525b; font-size: 11px; text-transform: uppercase; font-weight: 800; letter-spacing: 1px; margin: 0 0 5px 0;'>Indirizzo di Consegna</p>
            <p style='color: #e4e4e7; font-size: 14px; margin: 0; line-height: 1.5;'><strong>{$e($name)}</strong><br>{$e($address)}<br>{$e($postalCode)} {$e($city)} ({$e($country)})</p>
        </div><br>
        Ti avviseremo non appena il pacco verrà affidato al corriere espresso.";

    sendEmail($customerEmail, 'Conferma Ordine - BikerSOS', 'Ordine Confermato.', $orderHtml, 'Traccia Spedizione', SITE_URL . '/ordini');
}

// --- Router ------------------------------------------------------------

$path = str_replace('/index.php', '', parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
$method = $_SERVER['REQUEST_METHOD'];
$rawBody = file_get_contents('php://input');
$body = json_decode($rawBody, true) ?? [];

if ($method === 'POST' && $path === '/api/webhook') {
    if (!isValidStripeSignature($rawBody, $_SERVER['HTTP_STRIPE_SIGNATURE'] ?? '')) {
        http_response_code(400);
        exit('Firma Stripe non valida');
    }
    $event = json_decode($rawBody, true);
    if (($event['type'] ?? '') === 'checkout.session.completed') {
        saveOrder($event['data']['object']);
    }
    respond(200, ['received' => true]);
}

if ($method === 'POST' && $path === '/api/create-checkout') {
    $user = authenticate();
    $checkout = [
        'payment_method_types' => ['card'],
        'mode' => 'payment',
        'client_reference_id' => $user['id'],
        'success_url' => SITE_URL . '/ordini?payment=success',
        'cancel_url' => SITE_URL . '/vetrina',
        'line_items' => [[
            'price_data' => [
                'currency' => 'eur',
                'product_data' => ['name' => 'Bracciale NFC BikerSOS'],
                'unit_amount' => 1590,
            ],
            'quantity' => 1,
        ]],
        'shipping_address_collection' => ['allowed_countries' => ['IT', 'CH', 'FR', 'DE', 'ES']],
    ];

    $ch = curl_init('https://api.stripe.com/v1/checkout/sessions');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_USERPWD, STRIPE_SECRET_KEY . ':');
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($checkout));
    $response = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($status !== 200) {
        error_log("Stripe checkout fallito ($status): $response");
        respond(500, ['error' => 'Errore Stripe']);
    }
    respond(200, ['url' => json_decode($response, true)['url']]);
}

if ($method === 'POST' && $path === '/api/auth/register') {
    $email = trim($body['email'] ?? '');
    $password = $body['password'] ?? '';
    $name = $body['name'] ?? '';
    if ($email === '' || $password === '') {
        respond(400, ['error' => 'Email e password obbligatorie']);
    }
    if (!isValidEmail($email)) {
        respond(400, ['error' => 'Indirizzo email non valido']);
    }

    $db = getDB();
    try {
        $db->beginTransaction();
        $stmt = $db->prepare('INSERT INTO users (email, password_hash) VALUES (:email, :pass) RETURNING id');
        $stmt->execute(['email' => $email, 'pass' => password_hash($password, PASSWORD_BCRYPT, ['cost' => 10])]);
        $userId = $stmt->fetchColumn();

        $stmt = $db->prepare('INSERT INTO profiles (id, user_id, name) VALUES (:id, :user_id, :name) RETURNING id');
        $stmt->execute(['id' => uuidV4(), 'user_id' => $userId, 'name' => $name]);
        $profileId = $stmt->fetchColumn();
        $db->commit();
    } catch (PDOException $e) {
        $db->rollBack();
        if ($e->getCode() === '23505') {
            respond(409, ['error' => 'Email già registrata']);
        }
        error_log('Registrazione fallita: ' . $e->getMessage());
        respond(500, ['error' => 'Registrazione non riuscita']);
    }

    $token = issueToken(['id' => $userId, 'exp' => time() + TOKEN_TTL]);
    respondAndContinue(201, ['token' => $token, 'userId' => $userId, 'profileId' => $profileId]);

    $welcomeHtml = "
        La tua registrazione è andata a buon fine.<br><br>
        Ora fai parte dell'infrastruttura BikerSOS. Il tuo account è attivo e pronto per essere configurato con i tuoi dati salvavita.<br><br>
        Accedi subito alla tua <strong>Dashboard Medica</strong> per inserire il tuo gruppo sanguigno, eventuali allergie e i contatti telefonici ICE da chiamare in caso di emergenza.";
    sendEmail($email, 'Benvenuto in BikerSOS', 'Benvenuto a bordo, Pilota.', $welcomeHtml, 'Configura Dashboard', SITE_URL . '/dashboard');
    exit;
}

if ($method === 'POST' && $path === '/api/auth/login') {
    $stmt = getDB()->prepare('SELECT id, password_hash FROM users WHERE email = :email');
    $stmt->execute(['email' => $body['email'] ?? '']);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($body['password'] ?? '', $user['password_hash'])) {
        respond(401, ['error' => 'Credenziali errate']);
    }
    respond(200, ['token' => issueToken(['id' => $user['id'], 'exp' => time() + TOKEN_TTL])]);
}

if ($method === 'GET' && $path === '/api/profile') {
    $user = authenticate();
    $stmt = getDB()->prepare('SELECT * FROM profiles WHERE user_id = :user_id');
    $stmt->execute(['user_id' => $user['id']]);
    respond(200, $stmt->fetch(PDO::FETCH_ASSOC));
}

if ($method === 'PUT' && $path === '/api/profile') {
    $user = authenticate();

    // Il "+" del gruppo sanguigno può arrivare decodificato come spazio (es. "A ").
    $bloodType = $body['blood_type'] ?? null;
    if ($bloodType && str_ends_with($bloodType, ' ')) {
        $bloodType = str_replace(' ', '+', $bloodType);
    }

    try {
        $stmt = getDB()->prepare('UPDATE profiles SET name = :name, dob = :dob, photo_url = :photo_url, blood_type = :blood_type, ice_name = :ice_name, ice_phone = :ice_phone, allergies = :allergies, conditions = :conditions, medications = :medications, updated_at = CURRENT_TIMESTAMP WHERE user_id = :user_id RETURNING *');
        $stmt->execute([
            'name' => $body['name'] ?? null,
            'dob' => $body['dob'] ?? null,
            'photo_url' => $body['photo_url'] ?? null,
            'blood_type' => $bloodType,
            'ice_name' => $body['ice_name'] ?? null,
            'ice_phone' => $body['ice_phone'] ?? null,
            'allergies' => $body['allergies'] ?? null,
            'conditions' => $body['conditions'] ?? null,
            'medications' => $body['medications'] ?? null,
            'user_id' => $user['id'],
        ]);
        respond(200, $stmt->fetch(PDO::FETCH_ASSOC));
    } catch (PDOException $e) {
        error_log('Aggiornamento profilo fallito: ' . $e->getMessage());
        respond(500, ['error' => 'Aggiornamento non riuscito']);
    }
}

if ($method === 'GET' && preg_match('/^\/api\/emergency\/([a-f0-9\-]{36})$/i', $path, $matches)) {
    $stmt = getDB()->prepare('SELECT ' . EMERGENCY_FIELDS . ' FROM profiles WHERE id = :id');
    $stmt->execute(['id' => $matches[1]]);
    $profile = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$profile) {
        respond(404, ['error' => 'Profilo non trovato']);
    }
    respond(200, $profile);
}

if ($method === 'GET' && $path === '/api/orders') {
    $user = authenticate();
    try {
        $stmt = getDB()->prepare('SELECT * FROM orders WHERE user_id = :user_id ORDER BY created_at DESC');
        $stmt->execute(['user_id' => $user['id']]);
        respond(200, $stmt->fetchAll(PDO::FETCH_ASSOC));
    } catch (PDOException $e) {
        error_log('Lettura ordini fallita: ' . $e->getMessage());
        respond(500, ['error' => 'Impossibile recuperare gli ordini']);
    }
}

if ($method === 'POST' && $path === '/api/forgot-password') {
    $email = trim($body['email'] ?? '');
    if ($email === '') {
        respond(400, ['error' => 'Email obbligatoria']);
    }

    $stmt = getDB()->prepare('SELECT id FROM users WHERE email = :email');
    $stmt->execute(['email' => $email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Risposta identica in ogni caso, per non rivelare quali email sono registrate.
    respondAndContinue(200, ['message' => 'Operazione presa in carico.']);

    if ($user) {
        $resetToken = issueToken(['id' => $user['id'], 'action' => 'reset', 'exp' => time() + RESET_TOKEN_TTL]);
        $resetHtml = 'Hai richiesto di reimpostare la password del tuo account. Clicca sul pulsante qui sotto per inserire una nuova chiave di sicurezza.<br><br>Se non hai richiesto questa operazione, puoi tranquillamente ignorare questa email.';
        sendEmail($email, 'Richiesta di Ripristino Password', 'Ripristina Accesso.', $resetHtml, 'Reimposta Password', SITE_URL . '/login/reset?token=' . $resetToken);
    }
    exit;
}

if ($method === 'POST' && $path === '/api/reset-password') {
    $token = $body['token'] ?? '';
    $newPassword = $body['password'] ?? '';
    if ($token === '' || $newPassword === '') {
        respond(400, ['error' => 'Dati mancanti']);
    }

    $claims = verifyToken($token, 'reset');
    if ($claims === null) {
        respond(400, ['error' => 'Link di ripristino scaduto o non valido.']);
    }

    $stmt = getDB()->prepare('UPDATE users SET password_hash = :pass WHERE id = :id');
    $stmt->execute(['pass' => password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => 10]), 'id' => $claims['id']]);
    respond(200, ['message' => 'Password aggiornata con successo!']);
}

respond(404, ['error' => 'Endpoint non trovato', 'path' => $path]);
