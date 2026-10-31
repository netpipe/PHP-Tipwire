<?php
/* ============================================================================
   TIPWIRE — Anonymous Crime Tip Line · single-file PHP + SQLite + libsodium
   ----------------------------------------------------------------------------
   Requires: PHP 8.1+ with the sodium extension (bundled by default).
   Run:      php -S 0.0.0.0:8080 tipwire.php
   Storage:  ./tipwire_data/  (auto-created: master key, sqlite db, .htaccess)
   Demo:     visit ?seed=demo on an empty board to load sample files.
   ============================================================================ */

declare(strict_types=1);

/* ----------------------------- configuration ----------------------------- */
const DUP_WINDOW_H     = 12;          // identical tip blocked if seen within N hours
const RATE_PER_HOUR    = 3;           // max tips per (hashed) IP per hour
const RATE_PER_DAY     = 8;           // max tips per (hashed) IP per day
const MAX_IMG_BYTES    = 8388608;     // 8 MiB photo limit
const PER_PAGE_OPTIONS = [10, 25, 50];
const RETENTION_DAYS   = 365;         // files auto-shredded after N days (0 = keep)
const MGMT_COOKIE_TTL  = 1800;        // manage session lifetime (seconds)
const AUTH_LOCKOUT     = 12;          // wrong-code attempts before a file locks
const MAX_BODY_CHARS   = 5000;
const MAX_WORDINDEX    = 200;

/* ------------------------------- utilities ------------------------------- */
function e(?string $s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function nowHour(): int { $t = time(); return $t - ($t % 3600); } // round to hour (timing hygiene)
function siteBase(): string { return basename($_SERVER['SCRIPT_NAME'] ?? 'tipwire.php'); }
function url(array $p = []): string {
    return siteBase() . ($p ? '?' . http_build_query($p) : '');
}
function absUrl(array $p = []): string {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
          || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $path = $_SERVER['SCRIPT_NAME'] ?? '/tipwire.php';
    return ($https ? 'https://' : 'http://') . $host . $path . ($p ? '?' . http_build_query($p) : '');
}
function fmtWhen(int $t): string { return strtoupper(date('d M Y', $t)) . ' · ≈' . date('H:00', $t) . ' UTC'; }
function fmtPid(string $pid): string { return strtoupper(substr($pid,0,4) . '-' . substr($pid,4)); }
function fmtToken(string $hex): string { return implode('-', str_split($hex, 4)); }
function parseToken(string $raw): ?string {
    $clean = strtolower(preg_replace('/[^0-9a-fA-F]/', '', $raw));
    return strlen($clean) === 32 ? $clean : null;
}
function excerpt(string $body, int $n = 230): string {
    $flat = trim(preg_replace('/\s+/u', ' ', $body));
    if (mb_strlen($flat) <= $n) return $flat;
    $cut = mb_substr($flat, 0, $n);
    $sp  = mb_strrpos($cut, ' ');
    if ($sp !== false && $sp > $n * 0.6) $cut = mb_substr($cut, 0, $sp);
    return $cut . ' …';
}
function normalizePlace(string $s): string {
    $s = trim(preg_replace('/\s+/u', ' ', $s));
    return function_exists('mb_convert_case')
        ? mb_convert_case(mb_strtolower($s), MB_CASE_TITLE, 'UTF-8')
        : ucwords(strtolower($s));
}

/* --------------------------- keys & cryptography -------------------------- */
function bootFs(): array {
    $dir = __DIR__ . '/tipwire_data';
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    if (!file_exists($dir . '/.htaccess')) {
        @file_put_contents($dir . '/.htaccess', "Require all denied\nDeny from all\n");
    }
    $keyFile = $dir . '/master.key';
    if (!is_file($keyFile)) {
        file_put_contents($keyFile, sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_ORIGINAL));
        @chmod($keyFile, 0600);
    }
    $b64 = file_get_contents($keyFile);
    $master = sodium_base642bin(trim((string)$b64), SODIUM_BASE64_VARIANT_ORIGINAL);
    if (strlen($master) !== SODIUM_CRYPTO_KDF_KEYBYTES) {
        http_response_code(500);
        exit('Master key corrupt — restore from backup or delete tipwire_data to start fresh.');
    }
    return [
        'dir'   => $dir,
        'enc'   => sodium_crypto_kdf_derive_from_key(32, 1, 'tw-enc01', $master), // sealing tips/photos
        'blind' => sodium_crypto_kdf_derive_from_key(32, 2, 'tw-blnd1', $master), // hashes: codes, fingerprints, words
        'mac'   => sodium_crypto_kdf_derive_from_key(32, 3, 'tw-mac01', $master), // flash + manage cookies
        'ip'    => sodium_crypto_kdf_derive_from_key(32, 4, 'tw-iph01', $master), // rate-limit IP hashing
    ];
}
function K(): array { static $k = null; return $k ??= bootFs(); }
function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO('sqlite:' . K()['dir'] . '/tips.sqlite');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec('PRAGMA journal_mode=WAL');
        $pdo->exec('PRAGMA synchronous=NORMAL');
        $pdo->exec('PRAGMA busy_timeout=5000');
        $pdo->exec('PRAGMA foreign_keys=ON');
        $pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS tips (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  pid         TEXT NOT NULL UNIQUE,
  city        TEXT NOT NULL,
  country     TEXT NOT NULL,
  body_enc    BLOB NOT NULL,
  img_enc     BLOB,
  img_type    TEXT,
  created_at  INTEGER NOT NULL,
  edited_at   INTEGER,
  auth_hash   TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  rate_ip     TEXT NOT NULL,
  auth_fails  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tips_created ON tips(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tips_loc     ON tips(country, city);
CREATE INDEX IF NOT EXISTS idx_tips_fp      ON tips(fingerprint, created_at);
CREATE TABLE IF NOT EXISTS tip_words (
  tip_id INTEGER NOT NULL REFERENCES tips(id) ON DELETE CASCADE,
  w      TEXT NOT NULL,
  UNIQUE(tip_id, w)
);
CREATE INDEX IF NOT EXISTS idx_words_w ON tip_words(w);
SQL);
    }
    return $pdo;
}
function seal(string $plain): string {           // XSalsa20-Poly1305, fresh nonce
    $n = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return $n . sodium_crypto_secretbox($plain, $n, K()['enc']);
}
function unseal(?string $blob): ?string {
    if ($blob === null || strlen($blob) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) return null;
    $n = substr($blob, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $p = sodium_crypto_secretbox_open(substr($blob, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $n, K()['enc']);
    return $p === false ? null : $p;
}
function blindHash(string $data, int $len = 16): string { // keyed generic hash → hex
    return sodium_bin2hex(sodium_crypto_generichash($data, K()['blind'], $len));
}
function authHashOf(string $token): string {
    return sodium_bin2hex(sodium_crypto_generichash($token, K()['blind'], 32));
}
function ipHash(): string { return blindHash($_SERVER['REMOTE_ADDR'] ?? 'unknown', 16); }
function makePid(): string {
    $alpha = '23456789abcdefghjkmnpqrstuvwxyz'; // no 0/O/1/i/l
    $bytes = random_bytes(8); $out = '';
    for ($i = 0; $i < 8; $i++) $out .= $alpha[ord($bytes[$i]) & 31]; // 256 % 32 == 0 → uniform
    return $out;
}
function newToken(): string { return sodium_bin2hex(random_bytes(16)); } // 32-char one-time code
function normWords(string $s): array {
    $stop = ['the','and','for','with','that','this','from','have','was','were','they','them','but','are'];
    $parts = preg_split('/[^\p{L}\p{N}]+/u', mb_strtolower($s)) ?: [];
    $out = [];
    foreach ($parts as $w) {
        if (mb_strlen($w) >= 3 && !in_array($w, $stop, true)) $out[$w] = true;
        if (count($out) >= MAX_WORDINDEX) break;
    }
    return array_keys($out);
}
function indexWords(int $tipId, string $body): void {
    $pdo = db(); $ins = $pdo->prepare('INSERT OR IGNORE INTO tip_words(tip_id,w) VALUES(?,?)');
    foreach (normWords($body) as $w) $ins->execute([$tipId, blindHash($w)]);
}
function fingerprintOf(string $body, string $city, string $country): string {
    $norm = trim(preg_replace('/\s+/u', ' ', mb_strtolower($body)));
    return blindHash($norm . '|' . mb_strtolower($city) . '|' . mb_strtolower($country), 32);
}

/* ------------------------ flash & manage-cookie layer --------------------- */
function flashSet(string $msg, string $type = 'ok'): void {
    $payload = json_encode(['m' => $msg, 't' => $type]);
    $mac = sodium_bin2hex(sodium_crypto_auth($payload, K()['mac']));
    setcookie('tw_fl', base64_encode($payload) . '.' . $mac, [
        'expires' => time() + 20, 'path' => '/', 'httponly' => true,
        'samesite' => 'Lax', 'secure' => !empty($_SERVER['HTTPS']),
    ]);
}
function flashTake(): ?array {
    $c = $_COOKIE['tw_fl'] ?? null;
    if (!$c) return null;
    setcookie('tw_fl', '', ['expires' => time() - 3600, 'path' => '/']);
    $dot = strrpos($c, '.');
    if ($dot === false) return null;
    [$b64, $mac] = [substr($c, 0, $dot), substr($c, $dot + 1)];
    $payload = base64_decode($b64, true);
    if ($payload === false || strlen($mac) !== 64) return null;
    if (!sodium_crypto_auth_verify(sodium_hex2bin($mac), $payload, K()['mac'])) return null;
    $j = json_decode($payload, true);
    return is_array($j) ? $j : null;
}
function mgrIssue(string $pid): void {
    $msg = $pid . '|' . (time() + MGMT_COOKIE_TTL);
    $mac = sodium_bin2hex(sodium_crypto_auth($msg, K()['mac']));
    setcookie('tw_mgr', $msg . '.' . $mac, [
        'expires' => time() + MGMT_COOKIE_TTL, 'path' => '/', 'httponly' => true,
        'samesite' => 'Lax', 'secure' => !empty($_SERVER['HTTPS']),
    ]);
}
function mgrClear(): void { setcookie('tw_mgr', '', ['expires' => time() - 3600, 'path' => '/']); }
function mgrPid(): ?string {
    $c = $_COOKIE['tw_mgr'] ?? null;
    if (!$c) return null;
    $dot = strrpos($c, '.');
    if ($dot === false) return null;
    [$msg, $mac] = [substr($c, 0, $dot), substr($c, $dot + 1)];
    if (strlen($mac) !== 64 || !sodium_crypto_auth_verify(sodium_hex2bin($mac), $msg, K()['mac'])) return null;
    $parts = explode('|', $msg);
    if (count($parts) !== 2 || (int)$parts[1] < time()) return null;
    return $parts[0];
}

/* ------------------------------- image input ------------------------------ */
function acceptImage(array $f): ?array { // returns [bytes, mime] or throws
    if (($f['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) return null;
    if ($f['error'] !== UPLOAD_ERR_OK) throw new RuntimeException('Upload failed (code ' . $f['error'] . ').');
    if ($f['size'] > MAX_IMG_BYTES)    throw new RuntimeException('Photo exceeds 8 MiB limit.');
    $bytes = file_get_contents($f['tmp_name']);
    if ($bytes === false) throw new RuntimeException('Could not read upload.');
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->buffer($bytes);
    $allow = ['image/jpeg','image/png','image/webp','image/gif'];
    if (!in_array($mime, $allow, true)) throw new RuntimeException('Photo must be JPG, PNG, WEBP or GIF.');
    if (@getimagesizefromstring($bytes) === false) throw new RuntimeException('File is not a valid image.');
    return [$bytes, $mime];
}

/* -------------------------------- data layer ------------------------------ */
function findByPid(string $pid): ?array {
    $st = db()->prepare('SELECT * FROM tips WHERE pid = ?');
    $st->execute([$pid]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}
function pruneExpired(): void {
    if (RETENTION_DAYS <= 0) return;
    $st = db()->prepare('DELETE FROM tips WHERE created_at < ?');
    $st->execute([nowHour() - RETENTION_DAYS * 86400]);
}
function tipCounts(): array {
    $row = db()->query('SELECT COUNT(*) AS n, COUNT(DISTINCT country) AS c, COUNT(DISTINCT city) AS t FROM tips')->fetch();
    return ['tips' => (int)$row['n'], 'countries' => (int)$row['c'], 'cities' => (int)$row['t']];
}
function tickerItems(): array {
    $st = db()->query('SELECT pid, city, country FROM tips ORDER BY created_at DESC, id DESC LIMIT 10');
    return $st->fetchAll(PDO::FETCH_ASSOC);
}
function countryOptions(): array {
    return db()->query('SELECT country, COUNT(*) n FROM tips GROUP BY country ORDER BY country')->fetchAll(PDO::FETCH_ASSOC);
}
function cityOptions(?string $country): array {
    if ($country !== null && $country !== '') {
        $st = db()->prepare('SELECT city, COUNT(*) n FROM tips WHERE country = ? GROUP BY city ORDER BY city');
        $st->execute([$country]);
        return $st->fetchAll(PDO::FETCH_ASSOC);
    }
    return db()->query('SELECT city, COUNT(*) n FROM tips GROUP BY city ORDER BY city')->fetchAll(PDO::FETCH_ASSOC);
}
function feedQuery(array $f): array {
    $where = []; $p = [];
    if ($f['q'] !== '') {
        $words = normWords($f['q']);
        if ($words) {
            $holders = [];
            foreach ($words as $i => $w) { $ph = ':w' . $i; $holders[] = $ph; $p[$ph] = blindHash($w); }
            $where[] = '(t.id IN (SELECT tip_id FROM tip_words WHERE w IN (' . implode(',', $holders)
                     . ') GROUP BY tip_id HAVING COUNT(DISTINCT w) = :wc) OR t.city LIKE :q OR t.country LIKE :q)';
            $p[':wc'] = count($words);
            $p[':q']  = '%' . $f['q'] . '%';
        } else {
            $where[] = '(t.city LIKE :q OR t.country LIKE :q)';
            $p[':q'] = '%' . $f['q'] . '%';
        }
    }
    if ($f['country'] !== '') { $where[] = 't.country = :country'; $p[':country'] = $f['country']; }
    if ($f['city']    !== '') { $where[] = 't.city = :city';       $p[':city']    = $f['city']; }
    $wsql = $where ? ' WHERE ' . implode(' AND ', $where) : '';
    $order = match ($f['sort']) {
        'old'     => 't.created_at ASC, t.id ASC',
        'city'    => 't.country ASC, t.city ASC, t.created_at DESC',
        'country' => 't.country ASC, t.city ASC, t.created_at DESC',
        default   => 't.created_at DESC, t.id DESC',
    };
    return [$wsql, $p, $order];
}

/* ------------------------------ tip creation ------------------------------ */
function insertTip(string $body, string $city, string $country, ?array $img, bool $demo = false, ?int $when = null): array {
    $pdo   = db();
    $body  = trim($body);
    $city  = normalizePlace($city);
    $country = normalizePlace($country);
    $fp    = fingerprintOf($body, $city, $country);
    $cut   = ($when ?? nowHour()) - DUP_WINDOW_H * 3600;

    // duplicate detector (recent identical file → reject)
    $st = $pdo->prepare('SELECT pid FROM tips WHERE fingerprint = ? AND created_at >= ? ORDER BY created_at DESC LIMIT 1');
    $st->execute([$fp, $cut]);
    if ($d = $st->fetch()) {
        throw new RuntimeException('Duplicate detected — this matches FILE ' . fmtPid($d['pid'])
            . ' posted within the last ' . DUP_WINDOW_H . 'h. Duplicate recent reports are auto-removed as spam.');
    }
    // rate limiting on salted-hash of IP (raw IP is never stored)
    if (!$demo) {
        $ip = ipHash();
        $st = $pdo->prepare('SELECT COUNT(*) FROM tips WHERE rate_ip = ? AND created_at >= ?');
        $st->execute([$ip, nowHour() - 3600]);
        if ((int)$st->fetchColumn() >= RATE_PER_HOUR)
            throw new RuntimeException('Rate limit: this line can only accept ' . RATE_PER_HOUR . ' tips per hour from one location. Come back later.');
        $st = $pdo->prepare('SELECT COUNT(*) FROM tips WHERE rate_ip = ? AND created_at >= ?');
        $st->execute([$ip, nowHour() - 86400]);
        if ((int)$st->fetchColumn() >= RATE_PER_DAY)
            throw new RuntimeException('Rate limit: daily quota reached for this location.');
    }

    $pid = makePid();
    while (findByPid($pid)) $pid = makePid();
    $token = newToken();

    $pdo->beginTransaction();
    try {
        $st = $pdo->prepare(<<<'SQL'
INSERT INTO tips (pid, city, country, body_enc, img_enc, img_type, created_at, auth_hash, fingerprint, rate_ip)
VALUES (?,?,?,?,?,?,?,?,?,?)
SQL);
        $st->execute([
            $pid, $city, $country, seal($body),
            $img ? seal($img[0]) : null, $img ? $img[1] : null,
            $when ?? nowHour(), authHashOf($token), $fp, $demo ? 'demo' : ipHash(),
        ]);
        $id = (int)$pdo->lastInsertId();
        indexWords($id, $body);
        $pdo->commit();
    } catch (Throwable $ex) {
        $pdo->rollBack();
        throw $ex;
    }
    return ['pid' => $pid, 'token' => $token];
}

/* --------------------------------- layout --------------------------------- */
function pageTop(string $title, bool $noCache = false): void {
    if ($noCache) header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    $fl = flashTake();
    $counts = tipCounts();
    $tick = tickerItems();
    ?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?= e($title) ?> · TIPWIRE</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Ccircle cx='16' cy='16' r='9' fill='%23ffb324'/%3E%3C/svg%3E">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:ital,wght@0,400;0,500;0,600;0,700;1,400&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0a0f16; --bg1:#0d141d; --panel:#121c29; --panel2:#16222f;
  --line:#24354a; --line2:#31465f;
  --ink:#e9eef5; --mut:#93a5ba; --dim:#5f7188;
  --amber:#ffb324; --amber2:#ffd166; --red:#ff5449; --green:#3ddc97; --cyan:#4cc3ff;
  --disp:'Bebas Neue',Impact,sans-serif; --body:'IBM Plex Sans',system-ui,sans-serif; --mono:'IBM Plex Mono',monospace;
}
*{box-sizing:border-box} html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--body);font-size:15.5px;line-height:1.55;
  background-image:
    radial-gradient(1100px 600px at 12% -10%, rgba(255,179,36,.07), transparent 60%),
    radial-gradient(900px 700px at 105% 110%, rgba(76,195,255,.06), transparent 60%),
    radial-gradient(rgba(255,255,255,.035) 1px, transparent 1.5px);
  background-size:auto,auto,26px 26px;}
.scan{position:fixed;inset:0;pointer-events:none;z-index:60;
  background:repeating-linear-gradient(0deg,transparent 0 3px,rgba(255,255,255,.013) 3px 4px);}
a{color:var(--amber);text-decoration:none} a:hover{color:var(--amber2)}
.mono{font-family:var(--mono)} .small{font-size:12px} .dim{color:var(--dim)}
.wrap{max-width:1200px;margin:0 auto;padding:0 20px}

/* status strip */
.topbar{display:flex;align-items:center;gap:14px;border-bottom:1px solid var(--line);
  background:rgba(10,15,22,.85);padding:8px 20px;font-family:var(--mono);font-size:11px;
  letter-spacing:.14em;text-transform:uppercase;color:var(--mut);position:sticky;top:0;z-index:50;backdrop-filter:blur(6px)}
.rec{color:var(--red);display:inline-flex;align-items:center;gap:8px}
.rec::before{content:'';width:9px;height:9px;border-radius:50%;background:var(--red);
  box-shadow:0 0 10px var(--red);animation:pulse 1.5s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
.topbar .spacer{flex:1}
.topbar .clock{color:var(--green)}

/* masthead */
.mast{display:grid;grid-template-columns:1.5fr 1fr;gap:34px;align-items:end;padding:44px 0 26px}
.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.32em;color:var(--amber);text-transform:uppercase;margin-bottom:10px}
h1.logo{font-family:var(--disp);font-size:clamp(64px,10vw,124px);line-height:.86;margin:0;letter-spacing:.015em}
h1.logo a{color:var(--ink)} h1.logo .dot{color:var(--amber)}
.tag{font-size:17px;color:var(--mut);margin:14px 0 16px;max-width:46ch}
.cursor{display:inline-block;width:.6em;background:var(--amber);color:transparent;margin-left:6px;animation:blink 1.1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
.badges{display:flex;flex-wrap:wrap;gap:8px}
.badge{font-family:var(--mono);font-size:10px;letter-spacing:.16em;text-transform:uppercase;color:var(--mut);
  border:1px solid var(--line);padding:5px 9px;background:rgba(18,28,41,.6)}
.badge.g{color:var(--green);border-color:rgba(61,220,151,.35)}
.mast-r{display:flex;flex-direction:column;align-items:flex-start;gap:14px}
.btn{display:inline-block;font-family:var(--mono);text-transform:uppercase;letter-spacing:.12em;
  border:1px solid var(--amber);color:var(--amber);background:transparent;padding:11px 18px;cursor:pointer;
  transition:transform .15s ease, background .15s ease, box-shadow .15s ease;font-size:13px}
.btn:hover{background:rgba(255,179,36,.12);transform:translate(-2px,-2px);box-shadow:4px 4px 0 rgba(255,179,36,.25);color:var(--amber2)}
.btn-solid{background:var(--amber);color:#131313;font-weight:600}
.btn-solid:hover{background:var(--amber2);color:#131313}
.btn-big{font-size:16px;padding:16px 26px}
.btn-red{border-color:var(--red);color:var(--red)}
.btn-red:hover{background:rgba(255,84,73,.12);box-shadow:4px 4px 0 rgba(255,84,73,.25);color:var(--red)}
.btn-ghost{border-color:var(--line);color:var(--mut)}
.btn-ghost:hover{background:rgba(147,165,186,.08);box-shadow:4px 4px 0 rgba(147,165,186,.15);color:var(--ink)}
.statgrid{display:flex;gap:10px;flex-wrap:wrap}
.stat{border:1px solid var(--line);background:var(--panel);padding:8px 14px;min-width:92px}
.stat b{display:block;font-family:var(--disp);font-size:30px;color:var(--amber);letter-spacing:.04em;line-height:1}
.stat span{font-family:var(--mono);font-size:9.5px;letter-spacing:.18em;color:var(--dim);text-transform:uppercase}

/* ticker */
.ticker{border-block:1px solid var(--line);background:var(--bg1);overflow:hidden;white-space:nowrap}
.ticker-track{display:inline-flex;gap:56px;padding:8px 0;animation:tick 46s linear infinite;font-family:var(--mono);
  font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--mut)}
.ticker:hover .ticker-track{animation-play-state:paused}
.ticker-track b{color:var(--amber);font-weight:500}
.ticker-track .sep{color:var(--line2)}
@keyframes tick{to{transform:translateX(-50%)}}

/* nav */
.nav{display:flex;gap:6px;align-items:center;padding:14px 0;flex-wrap:wrap}
.nav a.nl{font-family:var(--mono);font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--mut);
  padding:8px 13px;border:1px solid transparent;transition:all .15s}
.nav a.nl:hover,.nav a.nl.on{color:var(--amber);border-color:var(--line);background:var(--panel)}
.nav .spacer{flex:1}

/* flash */
.flash{font-family:var(--mono);font-size:12.5px;padding:11px 15px;border:1px solid;margin:6px 0 0}
.flash.ok{border-color:rgba(61,220,151,.5);color:var(--green);background:rgba(61,220,151,.07)}
.flash.err{border-color:rgba(255,84,73,.5);color:var(--red);background:rgba(255,84,73,.07)}

/* layout */
.layout{display:grid;grid-template-columns:296px 1fr;gap:26px;padding:10px 0 60px;align-items:start}
aside.side{position:sticky;top:64px;display:flex;flex-direction:column;gap:16px}
.panel{background:var(--panel);border:1px solid var(--line);padding:18px}
.panel h3{font-family:var(--mono);font-size:11px;letter-spacing:.24em;text-transform:uppercase;color:var(--amber);margin:0 0 14px}
label.fl{display:block;font-family:var(--mono);font-size:10.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim);margin:12px 0 5px}
input[type=text],input[type=search],select,textarea{width:100%;background:var(--bg1);border:1px solid var(--line);
  color:var(--ink);padding:10px 12px;font-family:var(--body);font-size:14px;transition:border-color .15s, box-shadow .15s;border-radius:0}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--amber);box-shadow:0 0 0 3px rgba(255,179,36,.14)}
textarea{resize:vertical;min-height:150px;line-height:1.6}
select{appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--mut) 50%),linear-gradient(135deg,var(--mut) 50%,transparent 50%);
  background-position:calc(100% - 18px) 55%,calc(100% - 13px) 55%;background-size:5px 5px;background-repeat:no-repeat}
.hint{font-size:12px;color:var(--dim);margin-top:5px}

/* cards */
h2.sec{font-family:var(--disp);font-size:34px;letter-spacing:.05em;margin:6px 0 16px}
h2.sec em{font-style:normal;color:var(--amber)}
.card{position:relative;background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--amber);
  clip-path:polygon(0 0,calc(100% - 18px) 0,100% 18px,100% 100%,0 100%);
  display:grid;grid-template-columns:92px 1fr auto;transition:transform .2s ease,border-color .2s,box-shadow .2s}
.card:hover{transform:translateY(-3px);border-color:var(--line2);border-left-color:var(--amber);
  box-shadow:0 14px 30px rgba(0,0,0,.45), 0 0 0 1px rgba(255,179,36,.12)}
.rail{border-right:1px dashed var(--line);padding:16px 12px;display:flex;flex-direction:column;align-items:center;gap:12px}
.pid{font-family:var(--mono);font-size:11px;color:var(--amber);letter-spacing:.08em;writing-mode:vertical-rl;text-orientation:mixed}
.barcode{width:34px;height:52px;background:repeating-linear-gradient(90deg,var(--line2) 0 2px,transparent 2px 5px);opacity:.7}
.card-main{padding:16px 20px;min-width:0}
.excerpt{margin:0 0 12px;color:#cfd9e5}
.meta{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.chip{font-family:var(--mono);font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;
  padding:4px 9px;border:1px solid;transition:all .15s}
.chip-city{color:var(--amber);border-color:rgba(255,179,36,.45)}
.chip-city:hover{background:var(--amber);color:#131313}
.chip-country{color:var(--cyan);border-color:rgba(76,195,255,.4)}
.chip-country:hover{background:var(--cyan);color:#0d141d}
.when{font-family:var(--mono);font-size:11px;color:var(--dim);letter-spacing:.06em}
.open{margin-left:auto;font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--mut);transition:color .15s}
.card:hover .open{color:var(--amber)}
.thumb{width:118px;min-height:100%;object-fit:cover;border-left:1px solid var(--line);display:block}
.stamp{position:absolute;top:10px;right:26px;transform:rotate(5deg);font-family:var(--mono);font-size:9px;
  letter-spacing:.22em;padding:3px 7px;border:1.5px solid;opacity:.85;text-transform:uppercase}
.stamp-g{color:var(--green);border-color:var(--green)}
.stamp-r{color:var(--red);border-color:var(--red)}

/* reveal on scroll */
.reveal{opacity:0;transform:translateY(16px);transition:opacity .55s ease,transform .55s ease}
.reveal.in{opacity:1;transform:none}

/* pager */
.pager{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-top:22px;font-family:var(--mono);font-size:12px}
.pager a,.pager span{padding:7px 11px;border:1px solid var(--line);color:var(--mut)}
.pager a:hover{border-color:var(--amber);color:var(--amber)}
.pager .cur{background:var(--amber);border-color:var(--amber);color:#131313;font-weight:600}
.pager .gap{border:none;color:var(--dim)}
.resline{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim);margin-bottom:12px}

/* empty state */
.empty{border:1px dashed var(--line2);padding:52px 30px;text-align:center;color:var(--mut)}
.empty .big{font-family:var(--disp);font-size:30px;color:var(--ink);letter-spacing:.06em;margin-bottom:6px}

/* forms */
.formwrap{max-width:760px;margin:0 auto;padding:10px 0 70px}
.field-help{font-size:12.5px;color:var(--dim);margin-top:5px}
.counter{font-family:var(--mono);font-size:11px;color:var(--dim);text-align:right;margin-top:4px}
.hp{position:absolute;left:-9999px;opacity:0;height:0;overflow:hidden}
.notice{border:1px solid rgba(255,179,36,.4);background:rgba(255,179,36,.06);padding:14px 16px;font-size:13.5px;color:var(--amber2)}
.receipt{display:flex;flex-direction:column;gap:14px}
.kv{display:grid;grid-template-columns:150px 1fr;gap:6px 14px;font-size:14px}
.kv dt{font-family:var(--mono);font-size:10.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim);padding-top:2px}
.kv dd{margin:0;word-break:break-word}
.codebox{font-family:var(--mono);font-size:clamp(15px,3vw,22px);letter-spacing:.14em;color:var(--amber);
  border:1px dashed rgba(255,179,36,.6);background:rgba(255,179,36,.05);padding:16px;display:flex;gap:14px;
  align-items:center;justify-content:space-between;flex-wrap:wrap}
.copybtn{font-family:var(--mono);font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;cursor:pointer;
  background:none;border:1px solid var(--line);color:var(--mut);padding:6px 10px;transition:all .15s}
.copybtn:hover{border-color:var(--amber);color:var(--amber)}
.copybtn.done{border-color:var(--green);color:var(--green)}
.sharegrid{display:grid;gap:10px}
.sharegrid .row{display:flex;gap:8px;align-items:center}
.sharegrid input{font-family:var(--mono);font-size:12px;color:var(--cyan)}

/* view page */
.viewgrid{display:grid;grid-template-columns:1fr 330px;gap:26px;padding:10px 0 70px;align-items:start}
.filebody{font-size:16.5px;line-height:1.75;white-space:pre-wrap;word-break:break-word}
.evidence img{max-width:100%;border:1px solid var(--line);display:block}
.dlist{display:flex;flex-direction:column;gap:8px;margin:0}
.dlist .row{display:flex;justify-content:space-between;gap:10px;border-bottom:1px dashed var(--line);padding:8px 0;
  font-family:var(--mono);font-size:12px;letter-spacing:.06em}
.dlist .row span:first-child{color:var(--dim);text-transform:uppercase;font-size:10.5px;letter-spacing:.18em;padding-top:2px}

/* browse */
.country-block{border:1px solid var(--line);background:var(--panel);margin-bottom:16px}
.country-head{display:flex;align-items:baseline;gap:14px;padding:14px 18px;border-bottom:1px solid var(--line)}
.country-head h3{font-family:var(--disp);font-size:26px;letter-spacing:.06em;margin:0;color:var(--amber)}
.country-head .n{font-family:var(--mono);font-size:11px;color:var(--dim);letter-spacing:.14em}
.cityrow{padding:14px 18px;display:flex;flex-wrap:wrap;gap:8px}

footer{border-top:1px solid var(--line);background:var(--bg1);padding:44px 0 34px;margin-top:20px}
.fgrid{display:grid;grid-template-columns:1.3fr 1fr;gap:36px}
footer h4{font-family:var(--mono);font-size:11px;letter-spacing:.24em;text-transform:uppercase;color:var(--amber);margin:0 0 14px}
footer li{margin:8px 0;color:var(--mut);font-size:13.5px}
footer .fine{margin-top:26px;font-family:var(--mono);font-size:10.5px;letter-spacing:.12em;color:var(--dim);text-transform:uppercase}
.okdot{color:var(--green)}

@media (max-width:960px){
  .mast{grid-template-columns:1fr} .layout{grid-template-columns:1fr} aside.side{position:static}
  .viewgrid,.fgrid{grid-template-columns:1fr} .card{grid-template-columns:70px 1fr} .thumb{display:none}
}
</style>
</head>
<body>
<div class="scan" aria-hidden="true"></div>
<div class="topbar">
  <span class="rec">Encrypted line active</span>
  <span class="spacer"></span>
  <span>SODIUM SEALED</span>
  <span class="clock" id="utc">--:--:-- UTC</span>
</div>
<div class="wrap">
  <header class="mast">
    <div>
      <div class="eyebrow">Anonymous crime tip line · public case board</div>
      <h1 class="logo"><a href="<?= e(url()) ?>">TIPWIRE<span class="dot">.</span></a></h1>
      <p class="tag">Break the silence. Stay invisible. Reports are sealed with military-grade sodium encryption the moment you hit send.<span class="cursor">▮</span></p>
      <div class="badges">
        <span class="badge g">XSalsa20-Poly1305</span>
        <span class="badge">No accounts</span>
        <span class="badge">No IP logs — hashed &amp; discarded</span>
        <span class="badge">One-time codes</span>
      </div>
    </div>
    <div class="mast-r">
      <a class="btn btn-solid btn-big" href="<?= e(url(['do'=>'new'])) ?>">⚑ Submit a tip</a>
      <span class="mono small dim">free · anonymous · takes 30 seconds</span>
      <div class="statgrid">
        <div class="stat"><b><?= (int)$counts['tips'] ?></b><span>files sealed</span></div>
        <div class="stat"><b><?= (int)$counts['countries'] ?></b><span>countries</span></div>
        <div class="stat"><b><?= (int)$counts['cities'] ?></b><span>cities</span></div>
      </div>
    </div>
  </header>
</div>
<div class="ticker" aria-hidden="true"><div class="ticker-track">
<?php
    $itemsHtml = '';
    if (!$tick) {
        $itemsHtml = '<span>THE BOARD IS QUIET — BE THE FIRST TO SPEAK</span><span class="sep">◆</span>';
    }
    foreach ($tick as $t) {
        $itemsHtml .= '<span><b>FILE ' . e(fmtPid($t['pid'])) . '</b> · ' . e($t['city']) . ', ' . e($t['country']) . ' · SEALED</span><span class="sep">◆</span>';
    }
    echo $itemsHtml . $itemsHtml; // duplicated for seamless loop
?>
</div></div>
<div class="wrap">
  <nav class="nav">
    <a class="nl <?= $title === 'The Board' ? 'on' : '' ?>" href="<?= e(url()) ?>">The board</a>
    <a class="nl <?= $title === 'Directory' ? 'on' : '' ?>" href="<?= e(url(['do'=>'browse'])) ?>">City directory</a>
    <?php if (mgrPid()): ?>
      <a class="nl" href="<?= e(url(['do'=>'edit','id'=>mgrPid()])) ?>">Manage file</a>
      <a class="nl" href="<?= e(url(['do'=>'logout'])) ?>">End session</a>
    <?php endif; ?>
    <span class="spacer"></span>
    <a class="btn" href="<?= e(url(['do'=>'new'])) ?>">+ New file</a>
  </nav>
  <?php if ($fl): ?><div class="flash <?= e($fl['t']) === 'err' ? 'err' : 'ok' ?>" role="status"><?= e($fl['m']) ?></div><?php endif; ?>
<?php
}
function pageBottom(): void { ?>
</div><!-- /wrap -->
<footer>
  <div class="wrap fgrid">
    <div>
      <h4>How this line protects you</h4>
      <ul>
        <li><span class="okdot">▸</span> Tip bodies &amp; photos are sealed with <b>XSalsa20-Poly1305</b> before touching disk — the database file alone is unreadable.</li>
        <li><span class="okdot">▸</span> Your IP is never stored — only a keyed sodium hash lives long enough to stop spam.</li>
        <li><span class="okdot">▸</span> Timestamps are rounded to the hour to blunt timing correlation.</li>
        <li><span class="okdot">▸</span> Search runs over <b>blind word-indexes</b>: encrypted text stays searchable without ever being decryptable by the DB.</li>
        <li><span class="okdot">▸</span> Edit/delete requires the one-time code issued at submission. Codes are stored only as hashes.</li>
      </ul>
    </div>
    <div>
      <h4>Before you send</h4>
      <ul>
        <li>City &amp; country tags stay as plain text so the board remains browsable — keep personal details out of them.</li>
        <li>For violent emergencies in progress, call your local emergency number first. This board is not monitored live.</li>
        <li>Files auto-shred after <?= (int)RETENTION_DAYS ?> days.</li>
      </ul>
      <div class="fine">TIPWIRE v1.0 · single-file · PHP + SQLite + libsodium</div>
    </div>
  </div>
</footer>
<script>
(function(){
  var c=document.getElementById('utc');
  function tick(){var d=new Date();c.textContent=d.toISOString().substr(11,8)+' UTC';}
  if(c){tick();setInterval(tick,1000);}
  var io=new IntersectionObserver(function(es){es.forEach(function(x){
    if(x.isIntersecting){x.target.classList.add('in');io.unobserve(x.target);}});},{threshold:.08});
  document.querySelectorAll('.reveal').forEach(function(el,i){
    el.style.transitionDelay=(Math.min(i,8)*55)+'ms';io.observe(el);});
  document.querySelectorAll('[data-copy]').forEach(function(b){
    b.addEventListener('click',function(){
      var t=document.querySelector(b.getAttribute('data-copy'));if(!t)return;
      var v=t.value||t.textContent;
      function ok(){b.classList.add('done');var o=b.textContent;b.textContent='copied ✓';
        setTimeout(function(){b.classList.remove('done');b.textContent=o;},1600);}
      if(navigator.clipboard){navigator.clipboard.writeText(v).then(ok);}
      else{t.select&&t.select();document.execCommand('copy');ok();}
    });});
  var ta=document.querySelector('textarea[data-max]'),cn=document.getElementById('cnt');
  if(ta&&cn){var mx=+ta.dataset.max;var f=function(){cn.textContent=ta.value.length+' / '+mx;};ta.addEventListener('input',f);f();}
  document.querySelectorAll('form[data-confirm]').forEach(function(fm){
    fm.addEventListener('submit',function(ev){
      if(!window.confirm(fm.dataset.confirm)){ev.preventDefault();}
    });});
})();
</script>
</body></html>
<?php }

/* --------------------------------- pages ---------------------------------- */
function pageFeed(): void {
    pruneExpired();
    $q   = trim((string)($_GET['q'] ?? ''));
    $country = trim((string)($_GET['country'] ?? ''));
    $city    = trim((string)($_GET['city'] ?? ''));
    $sort = in_array($_GET['sort'] ?? '', ['new','old','city','country'], true) ? $_GET['sort'] : 'new';
    $per  = (int)($_GET['per'] ?? 10);
    if (!in_array($per, PER_PAGE_OPTIONS, true)) $per = 10;
    $pg = max(1, (int)($_GET['page'] ?? 1));
    $f = ['q'=>$q,'country'=>$country,'city'=>$city,'sort'=>$sort];
    [$wsql,$p,$order] = feedQuery($f);
    $pdo = db();
    $st = $pdo->prepare('SELECT COUNT(*) FROM tips t' . $wsql);
    $st->execute($p);
    $total = (int)$st->fetchColumn();
    $pages = max(1, (int)ceil($total / $per));
    $pg = min($pg, $pages);
    $off = ($pg - 1) * $per;
    $st = $pdo->prepare('SELECT id, pid, city, country, body_enc, img_type, created_at, edited_at,
                                (img_enc IS NOT NULL) AS has_img
                         FROM tips t' . $wsql . ' ORDER BY ' . $order . ' LIMIT ' . (int)$per . ' OFFSET ' . (int)$off);
    $st->execute($p);
    $rows = $st->fetchAll(PDO::FETCH_ASSOC);
    $countries = countryOptions();
    $cities = cityOptions($country !== '' ? $country : null);

    pageTop('The Board'); ?>
<div class="layout">
  <aside class="side">
    <form class="panel" method="get" action="<?= e(siteBase()) ?>">
      <h3>Filter the board</h3>
      <label class="fl" for="q">Search reports</label>
      <input type="search" id="q" name="q" value="<?= e($q) ?>" placeholder="words, city, country…">
      <div class="hint">Text search hits encrypted bodies via blind word-indexes.</div>
      <label class="fl" for="fcountry">Country</label>
      <select id="fcountry" name="country" onchange="this.form.submit()">
        <option value="">— all countries —</option>
        <?php foreach ($countries as $c): ?>
        <option value="<?= e($c['country']) ?>" <?= $c['country']===$country?'selected':'' ?>><?= e($c['country']) ?> (<?= (int)$c['n'] ?>)</option>
        <?php endforeach; ?>
      </select>
      <label class="fl" for="fcity">City</label>
      <select id="fcity" name="city" onchange="this.form.submit()">
        <option value="">— all cities —</option>
        <?php foreach ($cities as $c): ?>
        <option value="<?= e($c['city']) ?>" <?= $c['city']===$city?'selected':'' ?>><?= e($c['city']) ?> (<?= (int)$c['n'] ?>)</option>
        <?php endforeach; ?>
      </select>
      <label class="fl" for="fsort">Sort by</label>
      <select id="fsort" name="sort">
        <option value="new" <?= $sort==='new'?'selected':'' ?>>Newest first</option>
        <option value="old" <?= $sort==='old'?'selected':'' ?>>Oldest first</option>
        <option value="city" <?= $sort==='city'?'selected':'' ?>>City A–Z</option>
        <option value="country" <?= $sort==='country'?'selected':'' ?>>Country A–Z</option>
      </select>
      <label class="fl" for="fper">Results per page</label>
      <select id="fper" name="per">
        <?php foreach (PER_PAGE_OPTIONS as $o): ?>
        <option value="<?= $o ?>" <?= $o===$per?'selected':'' ?>><?= $o ?> per page</option>
        <?php endforeach; ?>
      </select>
      <div style="display:flex;gap:8px;margin-top:16px">
        <button class="btn" type="submit">Apply</button>
        <a class="btn btn-ghost" href="<?= e(url()) ?>">Reset</a>
      </div>
    </form>
    <div class="panel">
      <h3>Board status</h3>
      <dl class="dlist">
        <div class="row"><span>Files</span><span style="color:var(--amber)"><?= (int)tipCounts()['tips'] ?></span></div>
        <div class="row"><span>Dup window</span><span><?= (int)DUP_WINDOW_H ?>h</span></div>
        <div class="row"><span>Auto-shred</span><span><?= (int)RETENTION_DAYS ?>d</span></div>
      </dl>
    </div>
  </aside>
  <section>
    <h2 class="sec">LATEST <em>FILES</em></h2>
    <div class="resline"><?= (int)$total ?> file<?= $total===1?'':'s' ?><?= $q!==''?' matching “'.e($q).'”':'' ?><?= $country!==''?' · '.e($country):'' ?><?= $city!==''?' · '.e($city):'' ?> · page <?= (int)$pg ?>/<?= (int)$pages ?></div>
    <?php if (!$rows): ?>
      <div class="empty reveal">
        <div class="big">NO FILES ON THE BOARD</div>
        <p>The line is open and encrypted. If you saw something, say something.</p>
        <p><a class="btn btn-solid" href="<?= e(url(['do'=>'new'])) ?>">⚑ Submit the first tip</a></p>
      </div>
    <?php endif; ?>
    <?php foreach ($rows as $i => $r): $body = unseal($r['body_enc']) ?? '[decryption failed]'; ?>
    <article class="card reveal" style="margin-bottom:14px">
      <div class="rail"><span class="pid"><?= e(fmtPid($r['pid'])) ?></span><span class="barcode"></span></div>
      <div class="card-main">
        <span class="stamp stamp-g">Sealed</span>
        <p class="excerpt"><?= e(excerpt($body)) ?></p>
        <div class="meta">
          <a class="chip chip-city" href="<?= e(url(['city'=>$r['city'],'sort'=>$sort,'per'=>$per])) ?>"><?= e($r['city']) ?></a>
          <a class="chip chip-country" href="<?= e(url(['country'=>$r['country'],'sort'=>$sort,'per'=>$per])) ?>"><?= e($r['country']) ?></a>
          <span class="when"><?= e(fmtWhen((int)$r['created_at'])) ?><?= $r['edited_at'] ? ' · edited' : '' ?></span>
          <a class="open" href="<?= e(url(['do'=>'view','id'=>$r['pid']])) ?>">Open file →</a>
        </div>
      </div>
      <?php if ($r['has_img']): ?>
      <a href="<?= e(url(['do'=>'view','id'=>$r['pid']])) ?>"><img class="thumb" loading="lazy" src="<?= e(url(['do'=>'img','id'=>$r['pid']])) ?>" alt="Evidence photo for file <?= e(fmtPid($r['pid'])) ?>"></a>
      <?php endif; ?>
    </article>
    <?php endforeach; ?>
    <?php if ($pages > 1): ?>
    <nav class="pager">
      <?php
        $mk = fn(int $n, string $label, bool $cur = false, bool $disabled = false) =>
            $cur ? '<span class="cur">' . $label . '</span>'
                 : ($disabled ? '<span class="gap">' . $label . '</span>'
                 : '<a href="' . e(url(['q'=>$q,'country'=>$country,'city'=>$city,'sort'=>$sort,'per'=>$per,'page'=>$n])) . '">' . $label . '</a>');
        if ($pg > 1) echo $mk($pg - 1, '← prev');
        $win = [];
        foreach (range(1, $pages) as $n) {
            if ($n === 1 || $n === $pages || abs($n - $pg) <= 2) $win[] = $n;
        }
        $prev = 0;
        foreach ($win as $n) {
            if ($prev && $n > $prev + 1) echo $mk(0, '…', false, true);
            echo $mk($n, (string)$n, $n === $pg);
            $prev = $n;
        }
        if ($pg < $pages) echo $mk($pg + 1, 'next →');
      ?>
    </nav>
    <?php endif; ?>
  </section>
</div>
<?php pageBottom();
}

function pageNew(?array $err = null): void {
    pageTop('New File', true); ?>
<div class="formwrap">
  <h2 class="sec">OPEN A NEW <em>FILE</em></h2>
  <?php if ($err): ?><div class="flash err" role="alert"><?= e($err['msg']) ?></div><?php endif; ?>
  <div class="notice" style="margin-bottom:18px">
    Nothing here identifies you. No account, no email, no IP stored. After sending you'll receive a
    <b>share link</b> and a <b>one-time code</b> — the code is the only way to edit or delete your file later.
    <b>Save it somewhere safe; it is shown exactly once.</b>
  </div>
  <form class="panel" method="post" action="<?= e(url(['do'=>'new'])) ?>" enctype="multipart/form-data">
    <input type="hidden" name="_action" value="create">
    <div class="hp" aria-hidden="true"><label>Leave this empty<input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>
    <h3>The report</h3>
    <label class="fl" for="body">What happened? *</label>
    <textarea id="body" name="body" required maxlength="<?= MAX_BODY_CHARS ?>" data-max="<?= MAX_BODY_CHARS ?>"
      placeholder="Describe what you witnessed: who, what, where, when. No names of victims, and no details that could identify you."><?= e($err['old']['body'] ?? '') ?></textarea>
    <div class="counter" id="cnt">0 / <?= MAX_BODY_CHARS ?></div>
    <label class="fl" for="photo">Evidence photo — optional (JPG/PNG/WEBP/GIF ≤ 8 MiB)</label>
    <input type="file" id="photo" name="photo" accept="image/jpeg,image/png,image/webp,image/gif">
    <div class="field-help">Photos are encrypted as a blob, never stored on disk in the clear. Strip metadata concerns — originals are kept sealed.</div>
    <h3 style="margin-top:22px">Location tags</h3>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
      <div>
        <label class="fl" for="city">City *</label>
        <input type="text" id="city" name="city" required maxlength="60" list="dl-cities" value="<?= e($err['old']['city'] ?? '') ?>" placeholder="e.g. Manila">
      </div>
      <div>
        <label class="fl" for="country">Country *</label>
        <input type="text" id="country" name="country" required maxlength="60" list="dl-countries" value="<?= e($err['old']['country'] ?? '') ?>" placeholder="e.g. Philippines">
      </div>
    </div>
    <datalist id="dl-cities"><?php foreach (cityOptions(null) as $c): ?><option value="<?= e($c['city']) ?>"><?php endforeach; ?></datalist>
    <datalist id="dl-countries"><?php foreach (countryOptions() as $c): ?><option value="<?= e($c['country']) ?>"><?php endforeach; ?></datalist>
    <div class="field-help">These tags stay in plain text so the board can be browsed — keep them broad.</div>
    <div style="margin-top:22px;display:flex;gap:10px;align-items:center">
      <button class="btn btn-solid btn-big" type="submit">Seal &amp; submit ⚑</button>
      <span class="mono small dim">encrypted in transit &amp; at rest</span>
    </div>
  </form>
</div>
<?php pageBottom();
}

function pageReceipt(array $res): void {
    pageTop('File Sealed', true);
    $share  = absUrl(['do'=>'view','id'=>$res['pid']]);
    $manage = absUrl(['do'=>'manage','id'=>$res['pid']]);
    ?>
<div class="formwrap receipt">
  <h2 class="sec">FILE <em>SEALED</em> ✓</h2>
  <div class="notice">⚠ This page is shown <b>once</b>. Refreshing will not bring the code back. Copy everything below now.</div>
  <div class="panel">
    <h3>Your one-time manage code</h3>
    <div class="codebox"><span id="code1"><?= e(fmtToken($res['token'])) ?></span>
      <button class="copybtn" type="button" data-copy="#code1">copy code</button></div>
    <div class="field-help">Unlocks editing and deletion for FILE <?= e(fmtPid($res['pid'])) ?>. Stored on our side only as an unbreakable hash. After you save an edit, a fresh code is issued and this one dies.</div>
  </div>
  <div class="panel sharegrid">
    <h3>Links</h3>
    <label class="fl">Public share link</label>
    <div class="row"><input type="text" readonly id="lnk1" value="<?= e($share) ?>"><button class="copybtn" type="button" data-copy="#lnk1">copy</button></div>
    <label class="fl">Manage link (will still ask for the code)</label>
    <div class="row"><input type="text" readonly id="lnk2" value="<?= e($manage) ?>"><button class="copybtn" type="button" data-copy="#lnk2">copy</button></div>
  </div>
  <div style="display:flex;gap:10px;flex-wrap:wrap">
    <a class="btn btn-solid" href="<?= e(url(['do'=>'view','id'=>$res['pid']])) ?>">View your file</a>
    <a class="btn btn-ghost" href="<?= e(url()) ?>">Back to the board</a>
  </div>
</div>
<?php pageBottom();
}

function pageView(string $pid): void {
    $r = findByPid($pid);
    if (!$r) { http_response_code(404); pageTop('Missing'); echo '<div class="empty reveal" style="margin:40px 0"><div class="big">FILE NOT FOUND</div><p>It never existed, was deleted by its owner, or shredded by retention.</p><p><a class="btn" href="'.e(url()).'">Back to the board</a></p></div>'; pageBottom(); return; }
    $body = unseal($r['body_enc']) ?? '[decryption failed]';
    $st = db()->prepare('SELECT pid, city FROM tips WHERE city = ? AND id <> ? ORDER BY created_at DESC LIMIT 3');
    $st->execute([$r['city'], $r['id']]);
    $related = $st->fetchAll(PDO::FETCH_ASSOC);
    $share = absUrl(['do'=>'view','id'=>$r['pid']]);
    pageTop('File ' . fmtPid($r['pid'])); ?>
<div class="viewgrid">
  <section>
    <h2 class="sec">FILE <em><?= e(fmtPid($r['pid'])) ?></em></h2>
    <article class="card reveal" style="grid-template-columns:1fr;margin-bottom:18px">
      <div class="card-main" style="padding:24px 26px">
        <span class="stamp stamp-g">Sealed</span>
        <div class="filebody"><?= e($body) ?></div>
      </div>
    </article>
    <?php if ($r['img_enc']): ?>
    <div class="panel evidence">
      <h3>Evidence photo</h3>
      <img src="<?= e(url(['do'=>'img','id'=>$r['pid']])) ?>" alt="Evidence photo attached to file <?= e(fmtPid($r['pid'])) ?>">
    </div>
    <?php endif; ?>
  </section>
  <aside style="display:flex;flex-direction:column;gap:16px">
    <div class="panel">
      <h3>Case details</h3>
      <dl class="dlist">
        <div class="row"><span>Logged</span><span><?= e(fmtWhen((int)$r['created_at'])) ?></span></div>
        <?php if ($r['edited_at']): ?><div class="row"><span>Edited</span><span><?= e(fmtWhen((int)$r['edited_at'])) ?></span></div><?php endif; ?>
        <div class="row"><span>City</span><span><a class="chip chip-city" href="<?= e(url(['city'=>$r['city']])) ?>"><?= e($r['city']) ?></a></span></div>
        <div class="row"><span>Country</span><span><a class="chip chip-country" href="<?= e(url(['country'=>$r['country']])) ?>"><?= e($r['country']) ?></a></span></div>
        <div class="row"><span>Evidence</span><span><?= $r['img_enc'] ? '1 photo' : 'none' ?></span></div>
        <div class="row"><span>Status</span><span style="color:var(--green)">SEALED</span></div>
      </dl>
    </div>
    <div class="panel sharegrid">
      <h3>Share</h3>
      <div class="row"><input type="text" readonly id="sh1" value="<?= e($share) ?>"><button class="copybtn" type="button" data-copy="#sh1">copy</button></div>
      <a class="btn btn-ghost" href="<?= e(url(['do'=>'manage','id'=>$r['pid']])) ?>">Own this file? Manage it</a>
      <div class="field-help">Editing/deleting requires the one-time code issued when this file was created.</div>
    </div>
    <?php if ($related): ?>
    <div class="panel">
      <h3>Also from <?= e($r['city']) ?></h3>
      <?php foreach ($related as $rel): ?>
      <a style="display:block;font-family:var(--mono);font-size:12px;padding:7px 0;border-bottom:1px dashed var(--line)"
         href="<?= e(url(['do'=>'view','id'=>$rel['pid']])) ?>">▸ FILE <?= e(fmtPid($rel['pid'])) ?></a>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>
  </aside>
</div>
<?php pageBottom();
}

function pageManage(string $pid, ?string $error = null): void {
    $r = findByPid($pid);
    if (!$r) { http_response_code(404); flashSet('File not found.', 'err'); header('Location: ' . url()); exit; }
    pageTop('Manage File', true); ?>
<div class="formwrap" style="max-width:560px">
  <h2 class="sec">MANAGE FILE <em><?= e(fmtPid($pid)) ?></em></h2>
  <?php if ($error): ?><div class="flash err" role="alert"><?= e($error) ?></div><?php endif; ?>
  <form class="panel" method="post" action="<?= e(url(['do'=>'manage','id'=>$pid])) ?>">
    <input type="hidden" name="_action" value="auth">
    <h3>Enter your one-time code</h3>
    <label class="fl" for="code">Code (issued when the file was created)</label>
    <input type="text" id="code" name="code" class="mono" autocomplete="off" spellcheck="false"
      style="letter-spacing:.12em;font-size:16px" placeholder="XXXX-XXXX-XXXX-…" required>
    <div class="field-help">Dashes and spaces don't matter. <?= AUTH_LOCKOUT - (int)$r['auth_fails'] ?> attempts remain for this file.</div>
    <div style="display:flex;gap:10px;margin-top:18px">
      <button class="btn btn-solid" type="submit">Unlock</button>
      <a class="btn btn-ghost" href="<?= e(url(['do'=>'view','id'=>$pid])) ?>">Cancel</a>
    </div>
  </form>
</div>
<?php pageBottom();
}

function pageEdit(array $r, ?string $error = null, ?array $saved = null): void {
    $body = unseal($r['body_enc']) ?? '';
    pageTop('Edit File', true); ?>
<div class="formwrap">
  <h2 class="sec">EDIT FILE <em><?= e(fmtPid($r['pid'])) ?></em></h2>
  <?php if ($error): ?><div class="flash err" role="alert"><?= e($error) ?></div><?php endif; ?>
  <?php if ($saved): ?>
  <div class="flash ok" role="status">Changes sealed. Your code was rotated — the old one is now dead.</div>
  <div class="panel" style="margin-bottom:16px">
    <h3>New one-time code (shown once)</h3>
    <div class="codebox"><span id="code2"><?= e(fmtToken($saved['token'])) ?></span>
      <button class="copybtn" type="button" data-copy="#code2">copy code</button></div>
  </div>
  <?php endif; ?>
  <form class="panel" method="post" action="<?= e(url(['do'=>'edit','id'=>$r['pid']])) ?>" enctype="multipart/form-data">
    <input type="hidden" name="_action" value="update">
    <div class="hp" aria-hidden="true"><label>Leave this empty<input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>
    <label class="fl" for="body">Report text *</label>
    <textarea id="body" name="body" required maxlength="<?= MAX_BODY_CHARS ?>" data-max="<?= MAX_BODY_CHARS ?>"><?= e($body) ?></textarea>
    <div class="counter" id="cnt">0 / <?= MAX_BODY_CHARS ?></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:8px">
      <div>
        <label class="fl" for="city">City *</label>
        <input type="text" id="city" name="city" required maxlength="60" value="<?= e($r['city']) ?>">
      </div>
      <div>
        <label class="fl" for="country">Country *</label>
        <input type="text" id="country" name="country" required maxlength="60" value="<?= e($r['country']) ?>">
      </div>
    </div>
    <label class="fl">Evidence photo</label>
    <?php if ($r['img_enc']): ?>
      <img src="<?= e(url(['do'=>'img','id'=>$r['pid']])) ?>" alt="Current evidence photo" style="max-width:220px;border:1px solid var(--line);margin-bottom:8px;display:block">
      <label style="display:flex;gap:8px;align-items:center;font-size:13.5px;color:var(--mut)">
        <input type="checkbox" name="remove_img" value="1"> Remove current photo
      </label>
    <?php endif; ?>
    <label class="fl" for="photo">Replace with new photo (optional)</label>
    <input type="file" id="photo" name="photo" accept="image/jpeg,image/png,image/webp,image/gif">
    <div style="display:flex;gap:10px;margin-top:22px;flex-wrap:wrap;align-items:center">
      <button class="btn btn-solid" type="submit">Seal changes</button>
      <a class="btn btn-ghost" href="<?= e(url(['do'=>'view','id'=>$r['pid']])) ?>">View file</a>
    </div>
  </form>
  <form class="panel" style="margin-top:16px;border-color:rgba(255,84,73,.45)" method="post"
        action="<?= e(url(['do'=>'edit','id'=>$r['pid']])) ?>"
        data-confirm="Destroy FILE <?= e(fmtPid($r['pid'])) ?> permanently? This cannot be undone.">
    <input type="hidden" name="_action" value="delete">
    <h3 style="color:var(--red)">Danger zone</h3>
    <p class="dim small">Deleting wipes the encrypted body, photo, word-index and record from the database immediately.</p>
    <button class="btn btn-red" type="submit">🗑 Destroy this file</button>
  </form>
</div>
<?php pageBottom();
}

function pageBrowse(): void {
    $rows = db()->query('SELECT country, city, COUNT(*) n FROM tips GROUP BY country, city ORDER BY country, city')
               ->fetchAll(PDO::FETCH_ASSOC);
    $byCountry = [];
    foreach ($rows as $row) $byCountry[$row['country']][] = $row;
    pageTop('Directory'); ?>
<div style="padding:10px 0 70px;max-width:860px">
  <h2 class="sec">CITY <em>DIRECTORY</em></h2>
  <p class="dim" style="margin-top:-8px">Every location on the board. Pick one to pull its files.</p>
  <?php if (!$byCountry): ?>
    <div class="empty reveal"><div class="big">NOTHING FILED YET</div><p><a class="btn btn-solid" href="<?= e(url(['do'=>'new'])) ?>">⚑ Submit a tip</a></p></div>
  <?php endif; ?>
  <?php foreach ($byCountry as $country => $cities): $n = array_sum(array_column($cities,'n')); ?>
  <div class="country-block reveal">
    <div class="country-head">
      <h3><?= e($country) ?></h3>
      <span class="n"><?= (int)$n ?> FILE<?= $n===1?'':'S' ?> · <?= count($cities) ?> CIT<?= count($cities)===1?'Y':'IES' ?></span>
      <span style="flex:1"></span>
      <a class="btn btn-ghost" style="padding:7px 12px;font-size:11px" href="<?= e(url(['country'=>$country])) ?>">View all →</a>
    </div>
    <div class="cityrow">
      <?php foreach ($cities as $c): ?>
      <a class="chip chip-city" href="<?= e(url(['country'=>$country,'city'=>$c['city']])) ?>"><?= e($c['city']) ?> · <?= (int)$c['n'] ?></a>
      <?php endforeach; ?>
    </div>
  </div>
  <?php endforeach; ?>
</div>
<?php pageBottom();
}

function serveImage(string $pid): void {
    $st = db()->prepare('SELECT img_enc, img_type FROM tips WHERE pid = ?');
    $st->execute([$pid]);
    $r = $st->fetch(PDO::FETCH_ASSOC);
    if (!$r || !$r['img_enc']) { http_response_code(404); exit; }
    $raw = unseal($r['img_enc']);
    if ($raw === null) { http_response_code(500); exit; }
    header('Content-Type: ' . $r['img_type']);
    header('Content-Length: ' . strlen($raw));
    header('Cache-Control: no-store');
    echo $raw;
}

/* -------------------------------- demo seed -------------------------------- */
function seedDemo(): void {
    $pdo = db();
    if ((int)$pdo->query('SELECT COUNT(*) FROM tips')->fetchColumn() > 0) {
        flashSet('Demo seed skipped — the board already has files.', 'err');
        header('Location: ' . url()); exit;
    }
    $samples = [
        ['[DEMO] Two men in dark jackets have been prying the ATM side-panel at the petrol station on Marina Road every night this week, around 02:00. Silver van, no plates, idling by the car wash while they work.', 'Lagos', 'Nigeria'],
        ['[DEMO] A warehouse behind the old textile market sells counterfeit medicine packaged as antibiotics. Deliveries arrive Tuesday nights through the rear gate, white truck with a dented bumper.', 'Manila', 'Philippines'],
        ['[DEMO] Someone is dumping chemical drums into the culvert behind Elmwood Avenue. Strong solvent smell after midnight, happened three times this month. Fish dying in the creek below.', 'Detroit', 'United States'],
        ['[DEMO] Corrupt inspector at the vehicle registry is selling passed inspections for unroadworthy trucks. Cash only, no receipts, office desk at the far end of the hall.', 'São Paulo', 'Brazil'],
        ['[DEMO] A pickpocket ring works the U8 platform at rush hour — one blocks the doors, two take bags, a fourth receives them on the stairs. They rotate jackets between runs.', 'Berlin', 'Germany'],
        ['[DEMO] Illegal sand mining trucks use the service road near the river bend after sunset. Locals are paid to stay quiet; the access gate lock has been cut.', 'Pune', 'India'],
    ];
    $codes = '';
    $t = nowHour(); $i = 0;
    foreach ($samples as [$body, $city, $country]) {
        $res = insertTip($body, $city, $country, null, true, $t - ($i++ * 5 * 3600));
        $codes .= fmtPid($res['pid']) . '  ' . fmtToken($res['token']) . "\n";
    }
    @file_put_contents(K()['dir'] . '/demo-codes.txt',
        "TIPWIRE demo files — manage codes (use via ?do=manage&id=…)\n" . $codes);
    flashSet('6 demo files loaded. Their manage codes are in tipwire_data/demo-codes.txt — delete them before going live.', 'ok');
    header('Location: ' . url()); exit;
}

/* --------------------------------- actions --------------------------------- */
function actionCreate(): void {
    if (($_POST['_action'] ?? '') !== 'create') { header('Location: ' . url(['do'=>'new'])); exit; }
    if (trim((string)($_POST['website'] ?? '')) !== '') { pageReceipt(['pid' => makePid(), 'token' => newToken()]); exit; } // honeypot: pretend success
    $body = trim((string)($_POST['body'] ?? ''));
    $city = trim((string)($_POST['city'] ?? ''));
    $country = trim((string)($_POST['country'] ?? ''));
    try {
        if (mb_strlen($body) < 20)    throw new RuntimeException('Give the responders something to work with — at least 20 characters.');
        if (mb_strlen($body) > MAX_BODY_CHARS) throw new RuntimeException('Report too long (' . MAX_BODY_CHARS . ' char limit).');
        if ($city === '' || $country === '') throw new RuntimeException('City and country tags are required.');
        $img = acceptImage($_FILES['photo'] ?? ['error' => UPLOAD_ERR_NO_FILE]);
        $res = insertTip($body, $city, $country, $img);
        pageReceipt($res); exit;
    } catch (Throwable $ex) {
        pageNew(['msg' => $ex->getMessage(), 'old' => ['body'=>$body,'city'=>$city,'country'=>$country]]); exit;
    }
}
function actionManagePost(string $pid): void {
    $r = findByPid($pid);
    if (!$r) { header('Location: ' . url()); exit; }
    if ((int)$r['auth_fails'] >= AUTH_LOCKOUT) {
        pageManage($pid, 'This file is locked after too many wrong codes. The code was one-time — without it, the file cannot be managed.'); exit;
    }
    $token = parseToken((string)($_POST['code'] ?? ''));
    if ($token === null) { pageManage($pid, 'That does not look like a valid code format.'); exit; }
    if (!hash_equals(authHashOf($token), $r['auth_hash'])) {
        db()->prepare('UPDATE tips SET auth_fails = auth_fails + 1 WHERE id = ?')->execute([$r['id']]);
        pageManage($pid, 'Wrong code. Codes are one-time and case-insensitive — copy it exactly as issued.'); exit;
    }
    mgrIssue($pid);
    header('Location: ' . url(['do'=>'edit','id'=>$pid])); exit;
}
function actionEdit(string $pid): void {
    $r = findByPid($pid);
    if (!$r) { flashSet('File not found.', 'err'); header('Location: ' . url()); exit; }
    if (mgrPid() !== $pid) { header('Location: ' . url(['do'=>'manage','id'=>$pid])); exit; }
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') { pageEdit($r); exit; }
    $act = $_POST['_action'] ?? '';

    if ($act === 'delete') {
        db()->prepare('DELETE FROM tips WHERE id = ?')->execute([$r['id']]); // words cascade
        mgrClear();
        flashSet('FILE ' . fmtPid($pid) . ' destroyed. All encrypted material is gone.', 'ok');
        header('Location: ' . url()); exit;
    }
    if ($act !== 'update') { header('Location: ' . url(['do'=>'edit','id'=>$pid])); exit; }
    if (trim((string)($_POST['website'] ?? '')) !== '') { header('Location: ' . url(['do'=>'edit','id'=>$pid])); exit; }

    $body = trim((string)($_POST['body'] ?? ''));
    $city = normalizePlace(trim((string)($_POST['city'] ?? '')));
    $country = normalizePlace(trim((string)($_POST['country'] ?? '')));
    try {
        if (mb_strlen($body) < 20 || mb_strlen($body) > MAX_BODY_CHARS) throw new RuntimeException('Report text must be 20–' . MAX_BODY_CHARS . ' characters.');
        if ($city === '' || $country === '') throw new RuntimeException('City and country tags are required.');
        $pdo = db();
        // duplicate guard against other recent files
        $fp = fingerprintOf($body, $city, $country);
        $st = $pdo->prepare('SELECT pid FROM tips WHERE fingerprint = ? AND id <> ? AND created_at >= ? LIMIT 1');
        $st->execute([$fp, $r['id'], nowHour() - DUP_WINDOW_H * 3600]);
        if ($d = $st->fetch()) throw new RuntimeException('This edit duplicates FILE ' . fmtPid($d['pid']) . ' — recent duplicates are blocked.');
        // image handling
        $newImg = acceptImage($_FILES['photo'] ?? ['error' => UPLOAD_ERR_NO_FILE]);
        $imgEnc = $r['img_enc']; $imgType = $r['img_type'];
        if (!empty($_POST['remove_img'])) { $imgEnc = null; $imgType = null; }
        if ($newImg) { $imgEnc = seal($newImg[0]); $imgType = $newImg[1]; }
        // rotate the one-time code on every save
        $token = newToken();
        $pdo->beginTransaction();
        $st = $pdo->prepare('UPDATE tips SET body_enc=?, city=?, country=?, img_enc=?, img_type=?, fingerprint=?, edited_at=?, auth_hash=? WHERE id=?');
        $st->execute([seal($body), $city, $country, $imgEnc, $imgType, $fp, nowHour(), authHashOf($token), $r['id']]);
        $pdo->prepare('DELETE FROM tip_words WHERE tip_id = ?')->execute([$r['id']]);
        indexWords((int)$r['id'], $body);
        $pdo->commit();
        $r2 = findByPid($pid);
        pageEdit($r2, null, ['token' => $token]); exit;
    } catch (Throwable $ex) {
        $r['body_enc'] = seal($body); // show the user's attempted text back
        $r['city'] = $city; $r['country'] = $country;
        pageEdit($r, $ex->getMessage()); exit;
    }
}

/* --------------------------------- router ---------------------------------- */
$do  = (string)($_GET['do'] ?? '');
$pid = (string)($_GET['id'] ?? '');

if (($GET['seed'] ?? ($_GET['seed'] ?? '')) === 'demo') { seedDemo(); }

if ($do === 'img') { serveImage($pid); exit; }
if ($do === 'logout') { mgrClear(); flashSet('Manage session ended.', 'ok'); header('Location: ' . url()); exit; }

switch ($do) {
    case '':
        pageFeed();
        break;
    case 'new':
        $_SERVER['REQUEST_METHOD'] === 'POST' ? actionCreate() : pageNew();
        break;
    case 'view':
        pageView($pid);
        break;
    case 'manage':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (mgrPid() === $pid && $pid !== '') { header('Location: ' . url(['do'=>'edit','id'=>$pid])); exit; }
            actionManagePost($pid);
        } else {
            if (mgrPid() === $pid && $pid !== '') { header('Location: ' . url(['do'=>'edit','id'=>$pid])); exit; }
            pageManage($pid);
        }
        break;
    case 'edit':
        actionEdit($pid);
        break;
    case 'browse':
        pageBrowse();
        break;
    default:
        http_response_code(404);
        pageTop('Missing');
        echo '<div class="empty reveal" style="margin:40px 0"><div class="big">404 — SIGNAL LOST</div><p><a class="btn" href="' . e(url()) . '">Back to the board</a></p></div>';
        pageBottom();
}