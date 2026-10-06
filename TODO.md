# TODO — pebble_security

Problèmes restant à traiter, détectés lors de l'audit du 2026-10-06. Le code `src/` n'a **pas** été modifié. Chaque bug est figé par un test qui vérifie le comportement actuel : il faut l'adapter au moment de la correction.

## Sécurité

- [ ] **Signatures HMAC comparées avec `===`.** `src/JWT.php:239`.
  - `verify()` compare la signature attendue et la signature reçue avec `===`, dont la durée dépend du nombre d'octets communs. Fuite par timing exploitable en théorie pour forger une signature HS*.
  - Correctif : `return hash_equals(self::hmac($algo, $msg, $key), $signature);`.
  - Test : `tests/JWTTest.php::testHmacSignatureIsComparedWithStrictEqualityNotHashEquals`.
- [ ] **`$expectedAlg` optionnel dans `JWT::decode()` : confusion d'algorithme.** `src/JWT.php:98`.
  - Sans `$expectedAlg`, l'algorithme du header est pris tel quel. Un appelant qui vérifie des RS256 avec la clé publique PEM accepte un token HS256 signé avec cette même clé publique utilisée comme secret HMAC. `Token::import()` passe bien l'algorithme, mais pas les appels directs à `JWT::decode()`.
  - Correctif : rendre `$expectedAlg` obligatoire (changement de signature, version majeure), ou lever une exception quand il est absent et que `$verify` vaut `true`.
  - Test : `tests/JWTTest.php::testDecodeWithoutExpectedAlgAcceptsHs256SignedWithTheRsaPublicKey`.
- [ ] **ES256/384/512 signent en DER au lieu de R||S brut.** `src/JWT.php:215, 242`.
  - `openssl_sign()` renvoie une séquence ASN.1 DER (environ 70-72 octets pour ES256). La RFC 7518 impose la concaténation brute R||S (64, 96 ou 132 octets). Les tokens ES* de cette lib ne sont pas lisibles par les autres libs JWT, et elle rejette les leurs.
  - Correctif : convertir DER → R||S dans `sign()` et R||S → DER dans `verify()` pour les ES*. Les tokens ES* déjà émis deviennent invalides.
  - Test : `tests/JWTTest.php::testEs256SignatureIsDerEncodedNotRawRAndS`, `tests/JWTTest.php::testEs256TokenFromAStandardLibraryIsRejected`.
- [ ] **`Crypto` : IV déterministe dérivé de la clé, pas de MAC.** `src/Crypto.php:73-77`.
  - L'IV vaut les 16 premiers caractères de la clé. Le même message chiffré deux fois donne le même résultat, ce qui révèle les doublons. Sans MAC, le chiffré CBC est malléable : modifier un octet du bloc N modifie le même octet du clair au bloc N+1. Une mauvaise clé peut aussi renvoyer du bruit au lieu de `null` (padding valide par hasard, environ 1 fois sur 256).
  - Correctif : IV aléatoire `random_bytes()` préfixé au chiffré, plus un HMAC (encrypt-then-MAC) vérifié avec `hash_equals()`, ou passage à `aes-256-gcm`/`sodium_crypto_secretbox`. Les données déjà chiffrées ne seront plus lisibles sans mode de compatibilité.
  - Test : `tests/CryptoTest.php::testEncryptionIsDeterministic`, `tests/CryptoTest.php::testCiphertextIsMalleableWithoutMac`, `tests/CryptoTest.php::testWrongKeyCanDecodeToGarbage`.
- [ ] **`Crypto` : la clé est tronquée à 32 octets sans erreur.** `src/Crypto.php:43`.
  - `openssl_encrypt()` tronque silencieusement la clé `aes-256` à 32 octets (et complète une clé courte par des `\0`). Deux clés qui ne diffèrent qu'après le 32e octet donnent le même chiffré.
  - Correctif : dériver une clé de 32 octets (`hash('sha256', $key, true)` ou `hash_hkdf`).
  - Test : `tests/CryptoTest.php::testKeyBytesBeyond32AreIgnored`.
- [ ] **OTP généré avec `mt_rand()`.** `src/Hash.php:103`.
  - `mt_rand()` n'est pas cryptographiquement sûr et se prédit à partir de quelques sorties ou de la graine. De plus, `000000` ne sort jamais (borne basse à 1).
  - Correctif : `random_int(0, 10 ** $len - 1)`.
  - Test : `tests/HashTest.php::testOtpUsesMtRand`.
- [ ] **`Hash::uuid()` n'est pas un UUID v4.** `src/Hash.php:80`.
  - Les 13 premiers chiffres viennent de `uniqid()` (secondes et microsecondes en hexadécimal), donc prévisibles, et ni le quartet de version (`4`) ni la variante RFC 4122 ne sont posés. Le caractère de version est un chiffre de `uniqid()`. `Token` l'utilise comme identifiant de token.
  - Correctif : `random_bytes(16)`, puis poser les bits de version (`0x40`) et de variante (`0x80`), ou `sprintf` façon `ramsey/uuid`. Corriger aussi le docblock (l'exemple est un v1).
  - Test : `tests/HashTest.php::testUuidStartsWithTheUniqidTimestamp`, `tests/HashTest.php::testUuidVersionCharacterIsNotAlways4`.
- [ ] **Option `salt` passée à `password_hash()`.** `src/Password.php:64`.
  - Depuis PHP 8.0, l'option est ignorée et lève un warning « The "salt" option has been ignored ». `setSalt()` n'a aucun effet, et le warning peut devenir une exception selon le gestionnaire d'erreurs de l'application.
  - Correctif : supprimer l'option dans `hash()` et déprécier `setSalt()` (no-op).
  - Test : `tests/PasswordTest.php::testSaltIsIgnoredWithAWarning`.

## Bugs

- [ ] **`Crypto::decode()` renvoie `null` pour un clair `'0'` ou vide.** `src/Crypto.php:64`.
  - Le `?: null` final transforme tout clair « falsy » en `null`. `'0'` et `''` ne font pas l'aller-retour, et sont indiscernables d'une erreur.
  - Correctif : `$out = openssl_decrypt(...); return $out === false ? null : $out;`.
  - Test : `tests/CryptoTest.php::testFalsyPlaintextDecodesToNull`.
- [ ] **`Crypto` : IV calculé en caractères et non en octets.** `src/Crypto.php:76`.
  - `mb_substr()` coupe 16 caractères : une clé UTF-8 multi-octets produit un IV de plus de 16 octets. openssl le tronque et lève un warning à chaque appel.
  - Correctif : `substr()` au lieu de `mb_substr()` (le chiffré change pour ces clés), ou, mieux, IV aléatoire (voir « Sécurité »).
  - Test : `tests/CryptoTest.php::testMultibyteKeyProducesAnOversizedIv`.
- [ ] **`Password::verify()` rejette toujours le mot de passe `'0'`.** `src/Password.php:85`.
  - Le test `!$password` est vrai pour `'0'`.
  - Correctif : `if ($password === null || $password === '' || !$hash)`.
  - Test : `tests/PasswordTest.php::testPasswordZeroNeverVerifies`.
- [ ] **`JWT::decode()` refuse un payload vide.** `src/JWT.php:167`.
  - `parse()` teste `!$payload`, donc un token `JWT::encode([])` lève « Invalid segment encoding ». Sans impact pour `Token` (le payload contient toujours `uuid`).
  - Correctif : distinguer un JSON invalide (`json_decode` qui ne renvoie pas de tableau) d'un tableau vide.
  - Test : `tests/JWTTest.php::testEmptyPayloadCannotBeDecoded`.

## Dette / qualité

- [ ] `src/JWT.php:271-274` : `a()` retombe sur la clé en majuscules. Un header `alg: "hs256"` passe le contrôle « supported », puis `isHmac()` (sensible à la casse) l'envoie vers `openssl_verify()`, qui lève un warning. Le token est rejeté, mais pas pour la bonne raison. Même effet sur les claims (`EXP` est lu comme `exp`).
- [ ] `src/JWT.php:128-140` : un claim `nbf`/`iat`/`exp` à `0` ou non numérique est ignoré sans erreur.
- [ ] `src/Token.php:174` : la preuve est comparée avec `!==` au lieu de `hash_equals()` (il s'agit d'un sha1, impact faible).
- [ ] `src/Token.php:207` et `src/JWT.php:184` : `parseToken()` duplique `getBearerToken()`.
- [ ] `src/Token.php:186` : `generate()` modifie le payload (`iat`, `exp`). Un second appel sans `$exp` conserve l'ancien `exp`.
- [ ] `src/Crypto.php:40, 55` et `src/Password.php:71` : `?? ''` sur des paramètres déjà typés `string`, code mort.
- [ ] `src/JWT.php:7` : le docblock référence le draft 06 et non la RFC 7519. Le docblock de `$algs` parle de « HMAC » alors qu'il liste aussi RS*/ES*.
- [ ] `src/Hash.php` : méthodes sans types de paramètre ni de retour (`make`, `salt`, `uuid`). `Hash::email()` utilise sha1 sans clé, donc les emails courants se retrouvent par dictionnaire.
