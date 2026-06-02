import type { AxiosRequestConfig } from "axios";

/**
 * DPoP (RFC 9449) — sender-constrained refresh tokens for AppKit.
 *
 * Generates a non-extractable ECDSA P-256 keypair on first use, persists it to
 * IndexedDB so it survives reloads and is shared across browser tabs of the
 * same origin, and signs short-lived proof JWTs that the server validates on
 * session-creation and refresh requests.
 *
 * Security model (see todo/TODO.md and SECURITY.md):
 * - The private key is created with `extractable: false`, so even an attacker
 *   with same-origin JS access cannot exfiltrate it. They could USE it to
 *   sign proofs in-place (which is why DPoP doesn't defend against active
 *   XSS), but they cannot copy it and use it from elsewhere.
 * - Once the server pins our jkt to a refresh-token chain, only proofs signed
 *   by this keypair can refresh that session. A token exfiltrated from
 *   localStorage (extension, malware, browser sync leak) is useless without
 *   the corresponding key in IndexedDB.
 *
 * Failure mode: if WebCrypto/IndexedDB throw for any reason (private mode,
 * locked storage, broken browser), `signDPoPProof` rejects. Callers should
 * treat that as "send the request without a DPoP header" — the server will
 * issue/refresh an unbound session, which is the same security posture as
 * pre-DPoP AppKit.
 */

const DB_NAME = "manyrows-appkit-dpop";
const DB_VERSION = 1;
const STORE = "keys";
const KEY_ID = "session-keypair";

interface StoredKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

// Cache the keypair lookup at module scope so concurrent callers (multiple
// in-flight requests at startup) share one IndexedDB round-trip.
let cachedKeyPair: Promise<StoredKeyPair> | null = null;

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function loadStoredKey(): Promise<StoredKeyPair | null> {
  return openDB().then(
    (db) =>
      new Promise<StoredKeyPair | null>((resolve, reject) => {
        const tx = db.transaction(STORE, "readonly");
        const store = tx.objectStore(STORE);
        const req = store.get(KEY_ID);
        req.onsuccess = () => {
          const stored = req.result as StoredKeyPair | undefined;
          resolve(stored ?? null);
        };
        req.onerror = () => reject(req.error);
      })
  );
}

function saveKey(keyPair: StoredKeyPair): Promise<void> {
  return openDB().then(
    (db) =>
      new Promise<void>((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite");
        const store = tx.objectStore(STORE);
        const req = store.put(keyPair, KEY_ID);
        req.onsuccess = () => resolve();
        req.onerror = () => reject(req.error);
      })
  );
}

async function generateKey(): Promise<StoredKeyPair> {
  const kp = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    /* extractable */ false,
    ["sign", "verify"]
  );
  // generateKey returns a CryptoKeyPair; wrap into our shape.
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

async function getOrCreateKey(): Promise<StoredKeyPair> {
  if (cachedKeyPair) return cachedKeyPair;

  // The actual create-or-load is wrapped in a Web Lock named after our DB so
  // concurrent tabs of the same origin serialize at the "first key creation"
  // point. Without this, two tabs starting from a fresh IndexedDB can both
  // run loadStoredKey()→null→generateKey()→saveKey() in parallel; the loser
  // ends up with an in-memory key that doesn't match what's persisted, so a
  // reload would invalidate any sessions it just signed for. Web Locks is in
  // every modern browser (Chrome 69+, Firefox 96+, Safari 15.4+); on older
  // Safari we fall back to the unlocked path and accept the rare race.
  const promise = (async () => {
    const work = async (): Promise<StoredKeyPair> => {
      try {
        const stored = await loadStoredKey();
        if (stored && stored.publicKey && stored.privateKey) {
          return stored;
        }
      } catch {
        // fall through to generate fresh
      }
      const fresh = await generateKey();
      try {
        await saveKey(fresh);
      } catch {
        // If persistence fails (private mode, quota, etc.) still return the
        // in-memory key — the user can complete this session, but a reload
        // will generate a new one (and the previous bound session would be
        // lost).
      }
      return fresh;
    };

    const locks = (navigator as Navigator & { locks?: LockManager }).locks;
    if (locks && typeof locks.request === "function") {
      return locks.request(`${DB_NAME}:init`, work);
    }
    return work();
  })();

  cachedKeyPair = promise;

  // Don't trap a transient failure forever: clear the cache slot on rejection
  // so the next caller can retry from scratch.
  promise.catch(() => {
    if (cachedKeyPair === promise) cachedKeyPair = null;
  });

  return promise;
}

interface PublicJWK {
  kty: string;
  crv: string;
  x: string;
  y: string;
}

async function exportPublicJWK(publicKey: CryptoKey): Promise<PublicJWK> {
  const jwk = (await crypto.subtle.exportKey("jwk", publicKey)) as JsonWebKey;
  if (!jwk.kty || !jwk.crv || !jwk.x || !jwk.y) {
    throw new Error("dpop: exported JWK missing required fields");
  }
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

function base64URLEncode(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function utf8ToBase64URL(s: string): string {
  return base64URLEncode(new TextEncoder().encode(s));
}

function generateJTI(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64URLEncode(bytes);
}

function htuFromURL(url: string): string {
  // RFC 9449 §4.3: htu is the HTTP target URI without query or fragment.
  // The server reconstructs as scheme://host/path; we strip ? and # here
  // to match.
  const q = url.indexOf("?");
  if (q >= 0) url = url.substring(0, q);
  const f = url.indexOf("#");
  if (f >= 0) url = url.substring(0, f);
  return url;
}

/**
 * Sign a DPoP proof JWT for the given HTTP method and URL.
 *
 * Throws on any underlying crypto/storage failure. Callers should fall back
 * to sending the request without a DPoP header in that case (the server will
 * treat it as a non-DPoP request — for an unbound session that's fine, for a
 * bound session it'll be a 401 and the user re-authenticates).
 */
async function signDPoPProof(method: string, url: string): Promise<string> {
  const { publicKey, privateKey } = await getOrCreateKey();
  const jwk = await exportPublicJWK(publicKey);

  const header = { typ: "dpop+jwt", alg: "ES256", jwk };
  const payload = {
    htm: method.toUpperCase(),
    htu: htuFromURL(url),
    iat: Math.floor(Date.now() / 1000),
    jti: generateJTI(),
  };

  const signingInput = `${utf8ToBase64URL(JSON.stringify(header))}.${utf8ToBase64URL(
    JSON.stringify(payload)
  )}`;

  // WebCrypto returns the raw r||s concatenation for ECDSA, which is the
  // same format JWS uses for ES256 — no DER unwrapping needed.
  const sigBuf = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(signingInput)
  );

  return `${signingInput}.${base64URLEncode(sigBuf)}`;
}

/**
 * Augment an axios-style request config with a `DPoP` header signed for the
 * given method and URL. On any signing/storage failure, returns the base
 * config unchanged — the request goes out without a DPoP header, the server
 * will treat it as a non-DPoP request, and (for unbound sessions) everything
 * still works. For bound sessions, the server will 401 and the user will
 * need to re-authenticate, which is the correct behavior when the local
 * keypair is unrecoverable.
 *
 * `opts.cookieMode` short-circuits signing entirely. The session
 * credential is an HttpOnly cookie that JS cannot read — so there's
 * nothing for DPoP to bind, and the protection it offers (key-pinned
 * tokens against localStorage exfiltration) is moot because the token
 * never reaches localStorage. Cookie mode also has an htu-mismatch
 * issue when the install is fronted by a host-rewriting proxy
 * (Cloudflare-for-SaaS Worker pattern).
 */
export async function withDPoPHeader(
  method: string,
  url: string,
  base?: AxiosRequestConfig,
  opts?: { cookieMode?: boolean }
): Promise<AxiosRequestConfig> {
  const conf: AxiosRequestConfig = base ? { ...base } : {};
  if (opts?.cookieMode) return conf;
  try {
    const proof = await signDPoPProof(method, url);
    conf.headers = { ...(conf.headers ?? {}), DPoP: proof };
  } catch (e) {
    if (typeof console !== "undefined") {
      // eslint-disable-next-line no-console
      console.warn("[AppKit] DPoP signing failed; sending request without DPoP:", e);
    }
  }
  return conf;
}

