import { describe, it, expect } from "vitest";
import * as http from "node:http";
import * as crypto from "node:crypto";
import axios from "axios";
import { addSigningInterceptor } from "../src/integrations/axios.js";
import {
  newEd25519SigningKey,
  newEd25519VerifyingKey,
  verifyMessage,
  component,
} from "../src/index.js";
import type { HttpMessage, Algorithm } from "../src/index.js";

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

describe("axios interceptor", () => {
  it("signs requests and server can verify", async () => {
    const { publicKey, privateKey } = generateEd25519Keys();
    const signingKey = newEd25519SigningKey("axios-key", privateKey);
    const verifyingKey = newEd25519VerifyingKey("axios-key", publicKey);

    const server = await startServer(async (req, res) => {
      const msg = incomingToMessage(req, `http://${req.headers.host}`);
      try {
        const result = await verifyMessage(
          msg,
          async (keyId: string, _alg: Algorithm | undefined) => {
            if (keyId === "axios-key") return verifyingKey;
            throw new Error("key not found");
          },
        );
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(`verified:${result.keyId}`);
      } catch (e) {
        res.writeHead(401);
        res.end(String(e));
      }
    });

    try {
      const client = axios.create({ baseURL: server.url });
      addSigningInterceptor(client, { key: signingKey });

      const resp = await client.get("/resource");
      expect(resp.status).toBe(200);
      expect(resp.data).toBe("verified:axios-key");
    } finally {
      server.close();
    }
  });

  it("signs POST with custom params", async () => {
    const { publicKey, privateKey } = generateEd25519Keys();
    const signingKey = newEd25519SigningKey("ax-post", privateKey);
    const verifyingKey = newEd25519VerifyingKey("ax-post", publicKey);

    const server = await startServer(async (req, res) => {
      const msg = incomingToMessage(req, `http://${req.headers.host}`);
      try {
        const result = await verifyMessage(
          msg,
          async () => verifyingKey,
          {
            requiredComponents: [component("@method"), component("@path")],
          },
        );
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(result.label);
      } catch (e) {
        res.writeHead(401);
        res.end(String(e));
      }
    });

    try {
      const client = axios.create({ baseURL: server.url });
      addSigningInterceptor(client, {
        key: signingKey,
        label: "ax-sig",
      });

      const resp = await client.post("/api/data", { hello: "world" });
      expect(resp.status).toBe(200);
      expect(resp.data).toBe("ax-sig");
    } finally {
      server.close();
    }
  });
});
