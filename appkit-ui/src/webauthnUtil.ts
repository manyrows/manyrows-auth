// Helpers for converting between base64url-encoded JSON (what the server
// sends/expects) and ArrayBuffer (what the WebAuthn browser API uses).
//
// We don't rely on PublicKeyCredential.parseCreationOptionsFromJSON /
// parseRequestOptionsFromJSON because Safari only shipped them in 17.4 and
// older mobile devices won't have them. The conversions here are mechanical
// and small enough to inline.

export type Base64URLString = string;

export interface PublicKeyCredentialDescriptorJSON {
  id: Base64URLString;
  type: PublicKeyCredentialType;
  transports?: AuthenticatorTransport[];
}

export interface PublicKeyCredentialUserEntityJSON {
  id: Base64URLString;
  name: string;
  displayName: string;
}

export interface PublicKeyCredentialCreationOptionsJSON {
  rp: PublicKeyCredentialRpEntity;
  user: PublicKeyCredentialUserEntityJSON;
  challenge: Base64URLString;
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
  extensions?: AuthenticationExtensionsClientInputs;
}

export interface PublicKeyCredentialRequestOptionsJSON {
  challenge: Base64URLString;
  timeout?: number;
  rpId?: string;
  allowCredentials?: PublicKeyCredentialDescriptorJSON[];
  userVerification?: UserVerificationRequirement;
  extensions?: AuthenticationExtensionsClientInputs;
}

// Server may wrap options in `{ publicKey: ... }` (matching what the browser
// API expects) or send the inner object directly; both shapes are accepted.
export type CreationOptionsJSON =
  | PublicKeyCredentialCreationOptionsJSON
  | { publicKey: PublicKeyCredentialCreationOptionsJSON };

export type RequestOptionsJSON =
  | PublicKeyCredentialRequestOptionsJSON
  | { publicKey: PublicKeyCredentialRequestOptionsJSON };

// Shape of the registration response we send back to the server. Mirrors what
// go-webauthn's protocol.ParseCredentialCreationResponseBytes expects.
export interface AttestationCredentialJSON {
  id: string;
  rawId: Base64URLString;
  type: "public-key";
  authenticatorAttachment: AuthenticatorAttachment | null;
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  response: {
    clientDataJSON: Base64URLString;
    attestationObject: Base64URLString;
    transports: string[];
  };
}

// Shape of the assertion response we send back to the server. Mirrors what
// go-webauthn's protocol.ParseCredentialRequestResponseBytes expects.
export interface AssertionCredentialJSON {
  id: string;
  rawId: Base64URLString;
  type: "public-key";
  authenticatorAttachment: AuthenticatorAttachment | null;
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  response: {
    clientDataJSON: Base64URLString;
    authenticatorData: Base64URLString;
    signature: Base64URLString;
    userHandle: Base64URLString | null;
  };
}

export function isPasskeySupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined" &&
    typeof navigator !== "undefined" &&
    !!navigator.credentials
  );
}

function b64urlDecode(s: string): ArrayBuffer {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(s.length + ((4 - (s.length % 4)) % 4), "=");
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function b64urlEncode(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.byteLength; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unwrapPublicKey<T>(json: T | { publicKey: T }): T {
  return (json as { publicKey?: T }).publicKey ?? (json as T);
}

// Server sends CredentialCreation in WebAuthn JSON form (challenge / user.id /
// excludeCredentials[].id are base64url strings). Browser API needs them as
// BufferSource. This decodes only the binary fields, leaving everything else
// intact.
export function decodeCreationOptions(json: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
  // Pull the binary-coded fields out of the JSON shape so the spread doesn't
  // smuggle string-typed `id` fields into the DOM-typed output.
  const { challenge, user, excludeCredentials, ...rest } = unwrapPublicKey(json);
  const out: PublicKeyCredentialCreationOptions = {
    ...rest,
    challenge: b64urlDecode(challenge),
    user: { ...user, id: b64urlDecode(user.id) },
  };
  if (Array.isArray(excludeCredentials)) {
    out.excludeCredentials = excludeCredentials.map((c) => ({ ...c, id: b64urlDecode(c.id) }));
  }
  return out;
}

export function decodeRequestOptions(json: RequestOptionsJSON): PublicKeyCredentialRequestOptions {
  const { challenge, allowCredentials, ...rest } = unwrapPublicKey(json);
  const out: PublicKeyCredentialRequestOptions = {
    ...rest,
    challenge: b64urlDecode(challenge),
  };
  if (Array.isArray(allowCredentials)) {
    out.allowCredentials = allowCredentials.map((c) => ({ ...c, id: b64urlDecode(c.id) }));
  }
  return out;
}

// Encode the registration response (PublicKeyCredential from create()) as
// the JSON shape go-webauthn's protocol.ParseCredentialCreationResponseBytes
// expects — base64url for every binary field.
export function encodeAttestationResponse(cred: PublicKeyCredential): AttestationCredentialJSON {
  const att = cred.response as AuthenticatorAttestationResponse;
  // Newer Chromium exposes getTransports; we forward when available so the
  // server can store them. Older browsers omit it — fall back to [].
  type WithTransports = AuthenticatorAttestationResponse & { getTransports?: () => string[] };
  let transports: string[] = [];
  const maybe = att as WithTransports;
  if (typeof maybe.getTransports === "function") {
    try { transports = maybe.getTransports() ?? []; } catch { /* noop */ }
  }
  return {
    id: cred.id,
    rawId: b64urlEncode(cred.rawId),
    type: "public-key",
    authenticatorAttachment: (cred.authenticatorAttachment as AuthenticatorAttachment | null) ?? null,
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
    response: {
      clientDataJSON: b64urlEncode(att.clientDataJSON),
      attestationObject: b64urlEncode(att.attestationObject),
      transports,
    },
  };
}

// Encode the assertion response (PublicKeyCredential from get()) as JSON for
// protocol.ParseCredentialRequestResponseBytes.
export function encodeAssertionResponse(cred: PublicKeyCredential): AssertionCredentialJSON {
  const ass = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: b64urlEncode(cred.rawId),
    type: "public-key",
    authenticatorAttachment: (cred.authenticatorAttachment as AuthenticatorAttachment | null) ?? null,
    clientExtensionResults: cred.getClientExtensionResults?.() ?? {},
    response: {
      clientDataJSON: b64urlEncode(ass.clientDataJSON),
      authenticatorData: b64urlEncode(ass.authenticatorData),
      signature: b64urlEncode(ass.signature),
      userHandle: ass.userHandle ? b64urlEncode(ass.userHandle) : null,
    },
  };
}
