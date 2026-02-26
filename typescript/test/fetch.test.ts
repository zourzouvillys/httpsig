import { describe, it, expect } from "vitest";
import * as http from "node:http";
import * as crypto from "node:crypto";
import { createSigningFetch } from "../src/integrations/fetch.js";
import {
  newEd25519SigningKey,
  newEd25519VerifyingKey,
  verifyMessage,
  component,
} from "../src/index.js";
import type { HttpMessage, VerifyingKey, Algorithm } from "../src/index.js";

function generateEd25519Keys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return { publicKey, privateKey };
}

function startServer(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as { port: number };
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        close: () => server.close(),
      });
    });
  });
}

function incomingToMessage(req: http.IncomingMessage, baseUrl: string): HttpMessage {
  const url = new URL(req.url ?? "/", baseUrl);
  return {
    isRequest: true,
    method: req.method,
    url,
    headerValues(name: string): string[] {
      const v = req.headers[name.toLowerCase()];
      if (!v) return [];
      return Array.isArray(v) ? v : [v];
    },
  };
}

describe("fetch wrapper", () => {
  it("signs requests and server can verify", async () => {
    const { publicKey, privateKey } = generateEd25519Keys();
    const signingKey = newEd25519SigningKey("fetch-key", privateKey);
    const verifyingKey = newEd25519VerifyingKey("fetch-key", publicKey);

    const server = await startServer(async (req, res) => {
      const msg = incomingToMessage(req, `http://${req.headers.host}`);
      try {
        const result = await verifyMessage(
          msg,
          async (keyId: string, _alg: Algorithm | undefined) => {
            if (keyId === "fetch-key") return verifyingKey;
            throw new Error("key not found");
          },
        );
        res.writeHead(200);
        res.end(`verified:${result.keyId}`);
      } catch (e) {
        res.writeHead(401);
        res.end(String(e));
      }
    });

    try {
      const signedFetch = createSigningFetch({ key: signingKey });
      const resp = await signedFetch(`${server.url}/test`);
      expect(resp.status).toBe(200);
      const body = await resp.text();
      expect(body).toBe("verified:fetch-key");
    } finally {
      server.close();
    }
  });

  it("uses custom params", async () => {
    const { publicKey, privateKey } = generateEd25519Keys();
    const signingKey = newEd25519SigningKey("custom-key", privateKey);
    const verifyingKey = newEd25519VerifyingKey("custom-key", publicKey);

    const server = await startServer(async (req, res) => {
      const msg = incomingToMessage(req, `http://${req.headers.host}`);
      try {
        const result = await verifyMessage(
          msg,
          async () => verifyingKey,
          {
            requiredComponents: [component("@method"), component("content-type")],
          },
        );
        res.writeHead(200);
        res.end(result.label);
      } catch (e) {
        res.writeHead(401);
        res.end(String(e));
      }
    });

    try {
      const signedFetch = createSigningFetch({
        key: signingKey,
        label: "my-sig",
        params: () => ({
          components: [
            component("@method"),
            component("@path"),
            component("@authority"),
            component("content-type"),
          ],
          keyId: "custom-key",
          created: Math.floor(Date.now() / 1000),
        }),
      });

      const resp = await signedFetch(`${server.url}/api`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      expect(resp.status).toBe(200);
      const body = await resp.text();
      expect(body).toBe("my-sig");
    } finally {
      server.close();
    }
  });
});
