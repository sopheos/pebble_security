# CLAUDE.md — pebble_security

Ce fichier guide Claude Code quand il **maintient** cette librairie. Pour l'**utiliser** depuis un projet, voir le skill [`skills/pebble-security/`](skills/pebble-security/SKILL.md).

## Rôle

`sopheos/pebble_security`, namespace `Pebble\Security\`, PHP >= 8.1, extensions `openssl` et `mbstring`, aucune dépendance Composer runtime. La lib fournit :
- `JWT` : encodage/décodage JWT (HS*, RS*, ES*), sans dépendance externe ;
- `Token` : surcouche applicative de `JWT` (uuid, preuve liée à un appareil, `iat`/`exp`) ;
- `Crypto` : chiffrement symétrique `openssl_encrypt` en base64 ;
- `Password` : `password_hash`/`password_verify` en bcrypt ;
- `Hash` : hachage par longueur, chaînes aléatoires, « UUID », OTP, hachage d'email.

La lib contient plusieurs faiblesses de sécurité connues (voir [`TODO.md`](TODO.md), section « Sécurité »). Elles sont figées par des tests, pas corrigées.

## Commandes

```bash
composer install
vendor/bin/phpunit            # toute la suite
vendor/bin/phpunit --filter JWTTest
```

## Carte de `src/`

| Fichier | Rôle |
|---|---|
| `JWT.php` | `encode()`, `decode()` (signature puis `nbf`/`iat`/`exp` avec `$leeway`), `parse()`, `sign()`, `verify()`, `getBearerToken()`. Statiques `$leeway` et `$timestamp` |
| `Token.php` | Payload mutable (`add`/`del`/`get`), `generate($exp)` et `import($jwt)` qui passe toujours l'algorithme attendu à `JWT::decode()` |
| `TokenException.php` | `token_required` et `token_invalid` |
| `Exception.php` | Exception levée par `JWT` |
| `Crypto.php` | `encode()`/`decode()` en `aes-256-cbc` par défaut, IV dérivé de la clé |
| `Password.php` | bcrypt, `setCost()`, `setSalt()` (sans effet depuis PHP 8) |
| `Hash.php` | `make()` (md5/sha1/sha256/sha512 selon la longueur), `salt()`, `random()`, `uuid()`, `otp()`, `email()` |

## Tests

- PHPUnit 9.5. Un fichier par classe dans `tests/`.
- Les classes de test n'ont pas de namespace. Les méthodes s'appellent `testPhraseEnCamelCase`, les assertions passent par `self::assertSame`, et des bannières `// ----` séparent les sections.
- Les clés RSA et EC sont générées dans `JWTTest::setUpBeforeClass()` avec `openssl_pkey_new()` : aucune clé n'est versionnée.
- `JWT::$timestamp` et `JWT::$leeway` sont statiques : `JWTTest::tearDown()` les remet à `0` et `30`.
- Les warnings PHP attendus (sel ignoré, IV trop long) sont capturés par `set_error_handler()`, pas par `expectWarning()`.

## Conventions du code

Respecter le style existant, sans le « moderniser » au passage :
- pas de `declare(strict_types=1)` ;
- constantes de classe sans visibilité ;
- `if` d'une ligne sans accolades tolérés ;
- docblocks `@return static`, commentaires mélangeant anglais et français.

Une modification de comportement doit être répercutée dans `skills/pebble-security/` (SKILL.md, `references/api-reference.md`, `references/gotchas.md`) et dans le `README.md`.

Corriger `JWT` (signature ES*, `$expectedAlg` obligatoire) ou `Crypto` (IV aléatoire, MAC) **change le format** des tokens ou des chiffrés : les données existantes ne seront plus lisibles. Prévoir une version majeure ou un mode de compatibilité.

## Bugs connus

Ils sont listés dans [`TODO.md`](TODO.md). Chacun est **figé par un test** annoté `// BUG:` qui vérifie le comportement *actuel*, dans la section « Known bugs » du fichier de test de la classe concernée.

Pour corriger un bug :
1. Corriger `src/`.
2. Réécrire le test `// BUG:` pour qu'il vérifie le comportement attendu.
3. Mettre à jour l'entrée « (bug) » de `skills/pebble-security/references/gotchas.md` et le SKILL.md.
4. Retirer l'entrée de `TODO.md` (il ne liste que ce qui reste à faire).
