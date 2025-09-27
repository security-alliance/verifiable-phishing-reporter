#!/usr/bin/env node

import forge from "node-forge";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import http from "node:http";
import net, { isIP } from "node:net";
import stream from "node:stream";
import tls from "node:tls";
import { SocksClient } from "socks";
import tldts from "tldts";
import { RawData, WebSocket } from "ws";
import path from "node:path";
import crypto from "node:crypto";

const VERSION = "0.0.1";

const PORT = process.env.PORT ?? 8443;
const DATA_DIR =
  process.env.NODE_ENV === "development" || !process.env.HOME
    ? process.cwd()
    : path.join(process.env.HOME, ".config", "verifiable-phishing-reporter");
const HTTP_API_ENDPOINT = process.env.NODE_ENV === "development" ? "http://localhost:3000" : "https://api.securityalliance.org";
const WS_API_ENDPOINT = process.env.NODE_ENV === "development" ? "ws://localhost:4000" : "wss://api.securityalliance.org";

const NEW_ATTESTATION_ENDPOINT = `${WS_API_ENDPOINT}/tls-attestation/v1/attest?version=${VERSION}`;
const SUBMIT_ATTESTATION_ENDPOINT = `${HTTP_API_ENDPOINT}/phishing/v1/submit-attestation`;
const CONFIG_ENDPOINT = `${HTTP_API_ENDPOINT}/tls-attestation/v1/config`;

const loadRemoteConfigPromise = (async () => {
  const data = await fetch(CONFIG_ENDPOINT);
  const result = await data.json();
  if (!result.ok) throw new Error(result.error);
  return result.result as {
    include: string[];
    exclude: string[];
  };
})();

const localLocalExclusions = (async () => {
  try {
    const data = await readFile(path.join(DATA_DIR, "excluded.txt"), { encoding: "utf-8" });
    return data.split("\n");
  } catch {
    return [];
  }
})();

const shouldAttestConnection = async (host: string) => {
  const localExclusions = await localLocalExclusions;
  if (localExclusions.includes(host)) return false;

  if (isIP(host)) return true;
  const remoteConfig = await loadRemoteConfigPromise;

  const parsed = tldts.parse(host, { allowPrivateDomains: true });
  const parts = host.split(".");
  for (let i = 0; i <= parts.length; i++) {
    const check = parts.slice(i).join(".");
    if (check === parsed.publicSuffix) break;
    if (remoteConfig.include.includes(check)) return true;
    if (remoteConfig.exclude.includes(check)) return false;
  }
  return true;
};

const submitAttestation = async (requestId: number, hostname: string, filename: string, data: any, retry = true) => {
  log.debug(`[${requestId}] submitting attestation for connection to ${hostname}`);
  const resp = await fetch(SUBMIT_ATTESTATION_ENDPOINT, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(process.env.SEAL_API_KEY ? { authorization: `Bearer ${process.env.SEAL_API_KEY}` } : {}),
    },
    body: JSON.stringify(data),
  });

  const body = await resp.json();
  if (!body.ok) {
    log.debug(`[${requestId}] an internal error occurred while submitting attestation for connection to ${hostname}: ${body.error}`);
    return;
  }

  if (body.result.blocked.length === 0) {
    log.error(`[${requestId}] server did not block any urls (${filename})`);
  } else {
    log.success(`[${requestId}] server blocked the following urls: ${body.result.blocked.join(", ")}`);
  }

  if (body.result.retry?.length > 0 && retry) {
    log.debug(`[${requestId}] server requested retry, retrying in 10 seconds...`);
    setTimeout(() => {
      submitAttestation(requestId, hostname, filename, data, false);
    }, 1000 * 10);
  }
};

const processAttestation = (requestId: number, hostname: string, data: any) => {
  if (data.data.length === 0) {
    log.debug(`[${requestId}] not storing attestation because there is no data`);
    return;
  }

  const filename = `attestation-${hostname}-${Date.now()}.json`;
  log.debug(`[${requestId}] storing attestation at ${filename}`);

  writeFile(path.join(DATA_DIR, filename), JSON.stringify(data), { encoding: "utf-8" }).then(() => {
    submitAttestation(requestId, hostname, filename, data);
  });
};

//#regino colors
const colors = {
  reset: "\x1b[0m",
  gray: "\x1b[90m",
  red: "\x1b[31m",
  green: "\x1b[32m",
};

const log = {
  debug: (...args: any[]) => console.log(colors.gray, ...args, colors.reset),
  info: (...args: any[]) => console.log(colors.reset, ...args, colors.reset),
  error: (...args: any[]) => console.log(colors.red, ...args, colors.reset),
  success: (...args: any[]) => console.log(colors.green, ...args, colors.reset),
};

//#region command
enum Command {
  SendClientHello = 0,
  SendServerHello = 1,
  SendClientPlaintext = 2,
  SendClientCiphertext = 3,
  AckClientPlaintext = 4,
  SendServerPlaintext = 5,
  SendServerCiphertext = 6,
  Finalize = 7,
}

const encodeMessage = (command: number, ...data: Buffer[]) => {
  return Buffer.concat([Uint8Array.from([command]), ...data]);
};

const decodeMessage = (data: RawData) => {
  const dataArr = Array.isArray(data) ? Buffer.concat(data) : Buffer.isBuffer(data) ? data : Buffer.from(data);

  if (dataArr.length < 1) return undefined;

  return {
    command: dataArr.readUint8(0),
    data: dataArr.subarray(1),
  };
};

const encodeUint32BE = (val: number) => {
  const buf = Buffer.alloc(4);
  buf.writeUint32BE(val, 0);
  return buf;
};
//#endregion

//#region certificates
const generateCertificate = (
  validity: number,
  subject: forge.pki.CertificateField[],
  issuer: forge.pki.CertificateField[],
  extensions: any[],
  key?: forge.pki.rsa.PrivateKey,
) => {
  const now = Date.now();

  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = crypto.randomBytes(16).toString("hex");
  cert.validity.notBefore = new Date(now - 1000 * 60 * 60);
  cert.validity.notAfter = new Date(now + validity);

  cert.setSubject(subject);
  cert.setIssuer(issuer);
  cert.setExtensions(extensions);

  cert.sign(key ?? keys.privateKey, forge.md.sha256.create());
  return { key: keys.privateKey, cert };
};

const loadSelfSignedCA = async () => {
  const keyFilePath = path.join(DATA_DIR, "tls-attestation-proxy.key");
  const crtFilePath = path.join(DATA_DIR, "tls-attestation-proxy.crt");
  try {
    const key = forge.pki.privateKeyFromPem(await readFile(keyFilePath, { encoding: "utf-8" }));
    const cert = forge.pki.certificateFromPem(await readFile(crtFilePath, { encoding: "utf-8" }));
    log.debug(`[+] loaded ca cert from ${crtFilePath}`);
    return { key, cert };
  } catch {
    const attrs = [
      {
        name: "commonName",
        value: "TLS Attestation Proxy",
      },
    ];
    const { key, cert } = generateCertificate(1000 * 60 * 60 * 24 * 365 * 10, attrs, attrs, [
      {
        name: "basicConstraints",
        cA: true,
      },
      {
        name: "keyUsage",
        keyCertSign: true,
        digitalSignature: true,
        keyEncipherment: true,
      },
    ]);

    await writeFile(keyFilePath, forge.pki.privateKeyToPem(key), { encoding: "utf-8" });
    await writeFile(crtFilePath, forge.pki.certificateToPem(cert), { encoding: "utf-8" });
    log.debug(`[+] generated new self-signed ca and wrote it to ${crtFilePath}`);

    return { key, cert };
  }
};

const generateLeafCertificate = (() => {
  const certCache = new Map<string, { key: string; cert: string }>();

  return (caKey: forge.pki.rsa.PrivateKey, caCert: forge.pki.Certificate, hostname: string) => {
    const cached = certCache.get(hostname);
    if (cached) return cached;

    const { key, cert } = generateCertificate(
      1000 * 60 * 60 * 24 * 30,
      [
        {
          name: "commonName",
          value: hostname,
        },
      ],
      caCert.subject.attributes,
      [
        {
          name: "subjectAltName",
          altNames: [isIP(hostname) ? { type: 7, ip: hostname } : { type: 2, value: hostname }],
        },
      ],
      caKey,
    );

    const result = { key: forge.pki.privateKeyToPem(key), cert: forge.pki.certificateToPem(cert) };
    certCache.set(hostname, result);
    return result;
  };
})();
//#endregion

//#region utils
const tryParseTlsClientHello = async (socket: stream.Duplex): Promise<Buffer | undefined> => {
  return new Promise((resolve) => {
    const buffer: Buffer[] = [];

    const done = (data: Buffer | undefined) => {
      socket.removeListener("data", ondata);
      socket.pause();
      for (const buf of buffer) socket.unshift(buf);
      resolve(data);
    };

    const ondata = (data: Buffer) => {
      buffer.push(data);

      const arr = Buffer.concat(buffer);
      if (arr.length < 5) return;

      const contentType = arr.readUint8(0);
      const length = arr.readUint16BE(3);

      const isTLS = contentType === 0x16 && length < 4096;
      if (!isTLS) {
        done(undefined);
      } else if (arr.length >= 5 + length) {
        done(arr.subarray(0, 5 + length));
      }
    };

    socket.on("data", ondata);
  });
};
//#endregion

class StreamRecorder {
  public readonly chunks: [boolean, Buffer][] = [];

  private localChunks: Record<number, Buffer> = {};
  private nextChunkId = 0;

  public recordLocal(data: Buffer) {
    const chunkId = this.nextChunkId++;
    this.localChunks[chunkId] = data;
    return chunkId;
  }
  public commitRemote(id: number, data: Buffer) {
    this.chunks[id] = [false, data];
  }
  public commitLocal(id: number, localId: number) {
    this.chunks[id] = [true, this.localChunks[localId]];
  }
}

const createConnection = async (
  targetHost: string,
  targetPort: number,
): Promise<{ ok: true; socket: net.Socket } | { ok: false; err: unknown }> => {
  const proxy = process.env.PROXY;
  if (!proxy) {
    return new Promise((resolve) => {
      const handler = (e: Error) => resolve({ ok: false, err: e });
      const socket = net.connect({ host: targetHost, port: targetPort });
      socket.once("connect", () => {
        socket.removeListener("error", handler);
        resolve({ ok: true, socket: socket });
      });
      socket.once("error", handler);
    });
  }

  const url = new URL(proxy);
  if (url.protocol === "socks4:" || url.protocol === "socks5:") {
    try {
      const socksInfo = await SocksClient.createConnection({
        proxy: {
          host: url.hostname,
          port: parseInt(url.port),
          type: url.protocol === "socks4:" ? 4 : 5,
          userId: url.username,
          password: url.password,
        },
        command: "connect",
        destination: {
          host: targetHost,
          port: targetPort,
        },
      });

      return { ok: true, socket: socksInfo.socket };
    } catch (e: unknown) {
      return { ok: false, err: e };
    }
  }

  throw new Error("unsupported proxy " + proxy);
};

const normalizeHostname = (hostname: string) => {
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    const maybeV6 = hostname.substring(1, hostname.length - 1);
    return maybeV6;
  }
  return hostname;
};

const handleConnectRequest = async (
  caKey: forge.pki.rsa.PrivateKey,
  caCert: forge.pki.Certificate,
  req: http.IncomingMessage,
  clientSocket: stream.Duplex,
  requestId: number,
) => {
  // set up finalizers
  const finalizers: (() => void)[] = [];
  const cleanup = () => {
    const arr = Array.from(finalizers);
    finalizers.length = 0;
    arr.forEach((v) => v());
  };

  const migrateClientSocketFinalizers = (() => {
    const finalizer = () => clientSocket.end();
    const errorHandler = (e: Error) => log.debug(`[${requestId}] caught error on client to ${url}`, e);
    const closeHandler = () => cleanup();

    finalizers.push(finalizer);
    clientSocket.on("error", errorHandler);
    clientSocket.on("close", closeHandler);

    return (socket: tls.TLSSocket) => {
      clientSocket.removeListener("error", errorHandler);
      clientSocket.removeListener("close", closeHandler);

      finalizers[finalizers.indexOf(finalizer)] = () => socket.end();
      socket.setTimeout(5000);
      socket.addListener("timeout", () => socket.destroySoon());
      socket.addListener("end", () => socket.end());
      socket.addListener("error", errorHandler);
      socket.addListener("close", closeHandler);
    };
  })();

  // parse the request
  const url = new URL(`https://${req.url}`);
  const hostname = normalizeHostname(url.hostname);
  const serverPort = parseInt(url.port) || 443;

  const shouldAttest = await shouldAttestConnection(hostname);

  const connection = await createConnection(hostname, serverPort);
  if (!connection.ok) {
    const err: any = connection.err;
    if (err.code === "ENOTFOUND") {
      console.debug(`[${requestId}] could not resolve ${err.hostname}`);
      clientSocket.write("HTTP/1.1 502 Could not resolve hostname\r\n\r\n");
    } else {
      log.error(`[${requestId}] caught error on server to ${url}`, err);
      clientSocket.write("HTTP/1.1 502 Could not connect to upstream");
    }
    return;
  }
  const serverSocket = connection.socket;
  finalizers.push(() => serverSocket.end());
  serverSocket.on("close", () => cleanup());
  serverSocket.on("error", (e: any) => log.error(`[${requestId}] caught error in connection to remote for ${url}`, e));
  clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

  const directConnection = () => {
    console.debug(`[${requestId}] creating direct connection to ${url}`);

    clientSocket.pipe(serverSocket);
    serverSocket.pipe(clientSocket);
  };

  if (!shouldAttest) return directConnection();

  const hello = await tryParseTlsClientHello(clientSocket);
  if (hello === undefined) return directConnection();

  const recorder = new StreamRecorder();

  let localTlsServer: tls.TLSSocket | undefined;

  const ws = new WebSocket(NEW_ATTESTATION_ENDPOINT, { autoPong: true });
  ws.on("close", () => cleanup());
  ws.on("error", (e) => log.debug(`[${requestId}] caught error in connection to attestation server for ${url}`, e));
  ws.on("message", (data) => {
    const payload = decodeMessage(data);
    if (!payload) return;

    switch (payload.command) {
      case Command.SendServerHello: {
        if (payload.data[0] === 0) {
          ws.removeAllListeners();
          ws.close();
          directConnection();
        } else if (payload.data[0] === 1) {
          log.debug(`[${requestId}] beginning attestation for connection to ${url}`);
          const alpnLen = payload.data.readUint32BE(1);
          const alpn = payload.data.subarray(5, 5 + alpnLen).toString("utf-8");
          localTlsServer = new tls.TLSSocket(clientSocket, {
            ...generateLeafCertificate(caKey, caCert, url.hostname),
            secureProtocol: "TLS_method",
            ALPNProtocols: alpn ? [alpn] : undefined,
            isServer: true,
          });
          migrateClientSocketFinalizers(localTlsServer);
          localTlsServer.on("data", (data) => {
            ws.send(encodeMessage(Command.SendClientPlaintext, encodeUint32BE(recorder.recordLocal(data)), data));
          });
        } else if (payload.data[0] > 2) {
          const errLen = payload.data.readUint32BE(1);
          const err = payload.data.subarray(5, 5 + errLen).toString("utf-8");
          log.error(`[${requestId}] attestation server rejected connection: ${err}`);
        }
        break;
      }
      case Command.SendClientCiphertext: {
        serverSocket.write(payload.data);
        break;
      }
      case Command.AckClientPlaintext: {
        const chunkId = payload.data.readUint32BE(0);
        const localChunkId = payload.data.readUint32BE(4);
        recorder.commitLocal(chunkId, localChunkId);
        break;
      }
      case Command.SendServerPlaintext: {
        if (localTlsServer === undefined) throw new Error("attestation server sent server plaintext before server hello");
        if (localTlsServer.readyState !== "open") return;

        const chunkId = payload.data.readUint32BE(0);
        const chunk = payload.data.subarray(4);
        recorder.commitRemote(chunkId, chunk);
        localTlsServer.write(chunk);
        break;
      }
      case Command.Finalize: {
        ws.close();
        const strLen = payload.data.readUint32BE(0);
        const attestation = JSON.parse(payload.data.subarray(4, 4 + strLen).toString("utf-8"));
        processAttestation(requestId, hostname, {
          ...attestation,
          data: recorder.chunks.map((v) => [v[0], v[1].toString("base64")]),
        });
        break;
      }
    }
  });

  ws.once("open", () => {
    finalizers.push(() => {
      if (ws.readyState !== WebSocket.OPEN) return;

      log.debug(`[${requestId}] requesting attestation for connection to ${url}`);
      ws.send(encodeMessage(Command.Finalize));
    });

    ws.send(encodeMessage(Command.SendClientHello, hello));

    serverSocket.on("data", (data) => ws.send(encodeMessage(Command.SendServerCiphertext, data)));
  });
};

(async () => {
  if (!process.env.DEBUG) console.debug = () => {}; // eslint-disable-line

  try {
    await mkdir(DATA_DIR);
  } catch {}

  const shutdown = () => {
    log.debug("[+] shutting down tls attestation proxy...");
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
  process.on("uncaughtException", (e) => log.error(`[+] caught exception`, e));
  process.on("unhandledRejection", (e) => log.error(`[+] caught exception`, e));

  const { key, cert } = await loadSelfSignedCA();

  let requestId = 0;
  const server = http.createServer((req, res) => {
    const parsedUrl = new URL(req.url!);

    const clonedHeaders = { ...req.headers };
    delete clonedHeaders["proxy-connection"];
    clonedHeaders["connection"] = "close";

    const options: http.RequestOptions = {
      hostname: parsedUrl.hostname || req.headers.host?.split(":")[0],
      port: parsedUrl.port || 80,
      path: parsedUrl.pathname,
      method: req.method,
      headers: clonedHeaders,
    };

    const proxyReq = http.request(options, (proxyRes: http.IncomingMessage) => {
      res.writeHead(proxyRes.statusCode!, proxyRes.headers);
      proxyRes.pipe(res);
    });

    proxyReq.on("error", (err: Error) => {
      res.writeHead(502);
      res.end("Bad Gateway");
    });

    req.pipe(proxyReq);
  });
  server.on("connect", (req, clientSocket, head) => {
    const id = requestId++;
    clientSocket.unshift(head);
    handleConnectRequest(key, cert, req, clientSocket, id).catch((e) => {
      log.error(`[${id}] caught error while handling client connection`, e);
    });
  });
  server.on("error", (err) => log.error("[+] error in attestation proxy", err));
  server.on("close", () => shutdown());
  server.listen(PORT, () => {
    log.info(`[+] attestation proxy is running on port ${PORT}`);
    log.info(`[+] configure your application to use the following http proxy: http://localhost:${PORT}`);
  });
})();
