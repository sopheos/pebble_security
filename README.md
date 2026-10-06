# Pebble/Security

Outils de sécurité de sopheos pour PHP 8.1+ : JWT (HS*, RS*, ES*), tokens applicatifs, chiffrement symétrique, mots de passe bcrypt et fonctions de hachage.

La lib n'a aucune dépendance Composer. Elle s'appuie sur les extensions `openssl` et `mbstring`. Plusieurs faiblesses de sécurité sont connues et listées dans [`TODO.md`](TODO.md) : lire la section « Sécurité » avant d'utiliser `Crypto`, `Hash::otp()`, `Hash::uuid()` ou les algorithmes ES*.

## Installation

```bash
composer require sopheos/pebble_security
```

## Claude Code

Ce package fournit un skill Claude Code dans [`skills/pebble-security/`](skills/pebble-security/). Il documente les patterns d'usage et les pièges de la librairie : toujours passer l'algorithme attendu à `JWT::decode()`, signatures ES* non interopérables, `Crypto` déterministe et sans MAC, OTP et UUID non sûrs, etc.

Dans un projet qui dépend de `sopheos/pebble_security`, copie-le une fois dans `.claude/skills/` après `composer install` pour que Claude Code le charge automatiquement. Le nom du dossier doit correspondre au `name` déclaré dans `SKILL.md` :

```bash
cp -r vendor/sopheos/pebble_security/skills/pebble-security .claude/skills/pebble-security
```

Pour la maintenance de la lib elle-même, voir [`CLAUDE.md`](CLAUDE.md). Les bugs connus sont listés dans [`TODO.md`](TODO.md).

## JWT

`\Pebble\Security\JWT` ne contient que des méthodes statiques. Les erreurs lèvent `\Pebble\Security\Exception`.

* `encode(array $payload, string $key, string $algo = JWT::HS256, ?string $keyId = null, ?array $head = null) : string` Signe le payload. `$keyId` ajoute `kid` au header, `$head` y fusionne des champs. Pour RS*/ES*, `$key` est la clé privée PEM.
* `decode(string $jwt, string $key, bool $verify = true, ?string $expectedAlg = null) : array` Vérifie la signature, puis `nbf`, `iat` et `exp`, et renvoie le payload. Le préfixe `Bearer ` est accepté. **Toujours passer `$expectedAlg`** : sans lui, l'algorithme du header est cru sur parole (confusion d'algorithme). Pour RS*/ES*, `$key` est la clé publique PEM.
* `parse(string $jwt) : array` Découpe sans vérifier : `[$headb64, $bodyb64, $cryptob64, $header, $payload, $signature]`.
* `getBearerToken(string $token) : string` Retire le préfixe `Bearer `.
* `sign($msg, $key, $alg = JWT::HS256) : string` Signature binaire brute.
* `verify(string $msg, string $signature, string $key, string $alg = JWT::HS256) : bool` Vérifie une signature.
* `JWT::$leeway` Tolérance d'horloge en secondes (30 par défaut).
* `JWT::$timestamp` Horodatage forcé pour les tests (`0` = `time()`).

Algorithmes : `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`. Les signatures ES* sont produites au format DER et non R||S : elles ne sont pas interopérables avec les autres libs JWT.

```php
use Pebble\Security\JWT;

$jwt = JWT::encode(['sub' => 42, 'exp' => time() + 3600], $secret, JWT::HS256);
$payload = JWT::decode($jwt, $secret, true, JWT::HS256);
```

## Token

`\Pebble\Security\Token` encapsule un payload JWT avec un `uuid` et, en option, une preuve (`proof`) dont le sha1 est stocké dans le claim `hash`. Les erreurs lèvent `\Pebble\Security\TokenException` (`token_required` ou `token_invalid`).

* `__construct(string $url, string $key, string $alg, ?string $proof = null)` Initialise un payload avec un nouvel `uuid`.
* `init(array $payload = []) : static` Remplace le payload (garde son `uuid` s'il en a un) et réinjecte `uuid` et `hash`.
* `add(string $name, $value) : static` Ajoute un claim. `null` le supprime.
* `del(string $name) : static` Supprime un claim.
* `get(string $name, mixed $default = null) : mixed` Lit un claim.
* `url()`, `key()`, `alg()`, `uuid()`, `proof()`, `hash()`, `payload()` Accesseurs.
* `generate(int $exp = 0) : string` Ajoute `iat` (et `exp` = maintenant + `$exp` si non nul) puis encode.
* `import(string $token) : static` Décode avec l'algorithme du constructeur, vérifie la preuve si elle est définie, puis `init()` avec le payload reçu.
* `parseToken(string $token) : string` Retire le préfixe `Bearer `.

```php
use Pebble\Security\JWT;
use Pebble\Security\Token;

$jwt = (new Token('https://api.example', $secret, JWT::HS256, $deviceId))
    ->add('user', 42)
    ->generate(3600);

$token = (new Token('https://api.example', $secret, JWT::HS256, $deviceId))->import($header);
$userId = $token->get('user');
```

## Crypto

`\Pebble\Security\Crypto` chiffre en `aes-256-cbc` (par défaut) et renvoie du base64.

* `__construct($method = null)` / `make($method = null) : static` Méthode openssl, `aes-256-cbc` par défaut.
* `encode(string $str, string $key) : string` Chiffre. Renvoie `''` en cas d'échec.
* `decode(string $str, string $key) : ?string` Déchiffre. Renvoie `null` en cas d'échec, mais aussi pour un clair `'0'` ou vide.

**Attention** : l'IV est dérivé de la clé (même message → même chiffré), il n'y a pas de MAC (chiffré modifiable sans détection) et la clé est tronquée à 32 octets. Ne pas l'utiliser pour des données sensibles. Préférer `sodium_crypto_secretbox()`.

## Password

`\Pebble\Security\Password` hache en bcrypt.

* `setCost($cost)` Coût bcrypt. Ignoré s'il est falsy.
* `setSalt($salt)` **Sans effet** depuis PHP 8.0 : `hash()` lève alors un warning.
* `hash($password) : string` `password_hash()` en `PASSWORD_BCRYPT`.
* `verify($password, $hash) : bool` `password_verify()`. Renvoie `false` si l'un des deux est vide, y compris pour le mot de passe `'0'`.

## Hash

`\Pebble\Security\Hash` ne contient que des méthodes statiques.

* `make($string, $length = 40)` Hachage hexadécimal choisi par la longueur : 32 md5, 40 sha1, 64 sha256, 128 sha512. Toute autre longueur donne du sha1.
* `salt($length = 40)` Hachage de `random_bytes()`. Même règle de longueur.
* `random(int $length = 40) : string` Chaîne hexadécimale aléatoire (`random_bytes`).
* `uuid()` Chaîne au format UUID, construite avec `uniqid()` et 19 caractères aléatoires. **Ce n'est pas un UUID v4** : début prévisible, pas de bits de version.
* `otp(int $len = 6) : string` Code numérique complété par des zéros. **Utilise `mt_rand()`**, non sûr : préférer `random_int()`.
* `email(string $email) : ?string` `sha1(nom)@sha1(domaine).tld`, ou `null` si l'email est invalide.

## Tests

```bash
composer install
vendor/bin/phpunit
```

Les clés RSA et EC sont générées à la volée. Les bugs connus sont figés par des tests annotés `// BUG:` qui vérifient le comportement actuel.
