import { describe, it, expect } from "vitest";
import { decodeCreationOptions, encodeAttestationResponse, isPasskeySupported } from "../../webauthn";

// "hello" base64url-encoded
const HELLO_B64URL = "aGVsbG8";

function bufToStr(buf: ArrayBuffer | BufferSource): string {
  return new TextDecoder().decode(buf as ArrayBuffer);
}

describe("decodeCreationOptions", () => {
  const json = {
    rp: { name: "Acme" },
    user: { id: HELLO_B64URL, name: "u@example.com", displayName: "U" },
    challenge: HELLO_B64URL,
    pubKeyCredParams: [{ type: "public-key" as const, alg: -7 }],
    excludeCredentials: [{ id: HELLO_B64URL, type: "public-key" as const }],
  };

  it("decodes base64url binary fields to ArrayBuffers", () => {
    const out = decodeCreationOptions(json);
    expect(bufToStr(out.challenge)).toBe("hello");
    expect(bufToStr(out.user.id)).toBe("hello");
    expect(bufToStr(out.excludeCredentials![0].id)).toBe("hello");
    expect(out.pubKeyCredParams).toEqual(json.pubKeyCredParams);
  });

  it("accepts the {publicKey: ...} wrapped shape", () => {
    const out = decodeCreationOptions({ publicKey: json });
    expect(bufToStr(out.challenge)).toBe("hello");
  });
});

describe("encodeAttestationResponse", () => {
  it("encodes binary fields as base64url", () => {
    const bytes = new TextEncoder().encode("hello").buffer;
    const cred = {
      id: "cred-1",
      rawId: bytes,
      authenticatorAttachment: "platform",
      getClientExtensionResults: () => ({}),
      response: {
        clientDataJSON: bytes,
        attestationObject: bytes,
        getTransports: () => ["internal"],
      },
    } as unknown as PublicKeyCredential;
    const out = encodeAttestationResponse(cred);
    expect(out).toEqual({
      id: "cred-1",
      rawId: HELLO_B64URL,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: HELLO_B64URL,
        attestationObject: HELLO_B64URL,
        transports: ["internal"],
      },
    });
  });

  it("uses url-safe chars and strips padding for awkward byte lengths", () => {
    // 0xfb,0xff,0xfe → "+//+" in standard base64 → "-__-" url-safe (chars 62/63);
    // single byte 0xfb → "+w==" → "-w" (double padding stripped).
    const tricky = new Uint8Array([0xfb, 0xff, 0xfe]).buffer;
    const single = new Uint8Array([0xfb]).buffer;
    const cred = {
      id: "cred-2",
      rawId: tricky,
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({}),
      response: {
        clientDataJSON: single,
        attestationObject: tricky,
        getTransports: () => [],
      },
    } as unknown as PublicKeyCredential;
    const out = encodeAttestationResponse(cred);
    expect(out.rawId).toBe("-__-");
    expect(out.response.clientDataJSON).toBe("-w");
    expect(out.rawId).not.toMatch(/[+/=]/);
  });
});

describe("isPasskeySupported", () => {
  it("is false in jsdom (no PublicKeyCredential)", () => {
    expect(isPasskeySupported()).toBe(false);
  });
});
