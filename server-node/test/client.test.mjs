import { test } from "node:test";
import assert from "node:assert/strict";

import { ManyRowsServer, ManyRowsServerError } from "../dist/index.js";

function mockFetch(handler) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    return handler(url, init);
  };
  return { fn, calls };
}

const json = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const opts = (fetchFn) => ({
  baseUrl: "https://auth.example.com/", // trailing slash should be trimmed
  workspace: "acme",
  appId: "app-1",
  apiKey: "mr_abc_secret",
  fetch: fetchFn,
});

test("checkPermission builds the URL, query, and auth header", async () => {
  const m = mockFetch(() => json(200, { allowed: true, permission: "posts:read", accountId: "u1" }));
  const mr = new ManyRowsServer(opts(m.fn));

  const res = await mr.checkPermission("u1", "posts:read");
  assert.equal(res.allowed, true);

  const { url, init } = m.calls[0];
  assert.equal(init.method, "GET");
  assert.equal(init.headers["X-API-Key"], "mr_abc_secret");
  assert.match(url, /^https:\/\/auth\.example\.com\/x\/acme\/api\/v1\/apps\/app-1\/check-permission\?/);
  assert.match(url, /accountId=u1/);
  assert.match(url, /permission=posts%3Aread/);
});

test("createUser sends a JSON body and parses the result", async () => {
  const m = mockFetch(() => json(201, { user: { id: "u2", email: "a@b.com" }, created: true, roles: ["editor"] }));
  const mr = new ManyRowsServer(opts(m.fn));

  const res = await mr.createUser({ email: "a@b.com", roles: ["editor"] });
  assert.equal(res.created, true);
  assert.equal(res.user.id, "u2");

  const { init } = m.calls[0];
  assert.equal(init.method, "POST");
  assert.equal(init.headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(init.body), { email: "a@b.com", roles: ["editor"] });
});

test("non-2xx throws ManyRowsServerError carrying status and code", async () => {
  const m = mockFetch(() => json(404, { error: "error.notFound", message: "Not found" }));
  const mr = new ManyRowsServer(opts(m.fn));

  await assert.rejects(
    () => mr.getUser("missing"),
    (err) => {
      assert.ok(err instanceof ManyRowsServerError);
      assert.equal(err.status, 404);
      assert.equal(err.code, "error.notFound");
      assert.equal(err.message, "Not found");
      return true;
    },
  );
});

test("deleteUserFieldValue handles a 204 with no body", async () => {
  const m = mockFetch(() => new Response(null, { status: 204 }));
  const mr = new ManyRowsServer(opts(m.fn));

  const res = await mr.deleteUserFieldValue("f1", "u1");
  assert.equal(res, undefined);
  assert.equal(m.calls[0].init.method, "DELETE");
  assert.match(m.calls[0].url, /\/user-fields\/f1\/users\/u1$/);
});

test("listUsers omits undefined query params", async () => {
  const m = mockFetch(() => json(200, { members: [], total: 0, page: 0, pageSize: 50 }));
  const mr = new ManyRowsServer(opts(m.fn));

  await mr.listUsers({ search: "ali" });
  assert.match(m.calls[0].url, /\/users\?search=ali$/);
});

test("constructor validates required options", () => {
  assert.throws(() => new ManyRowsServer({ baseUrl: "", workspace: "a", appId: "b", apiKey: "c" }));
  assert.throws(() => new ManyRowsServer({ baseUrl: "x", workspace: "a", appId: "b", apiKey: "" }));
});
