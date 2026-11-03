/// <reference lib="webworker" />
/**
 * Runs Argon2id (64 MiB) off the main thread so the UI stays responsive.
 * The Master Key exists only inside this worker; only the auth key (to send)
 * and non-extractable CryptoKeys (structured-cloned) come back.
 */
import { deriveLoginKeys, prepareRegistration, preparePasswordChange } from '@zk-notes/crypto';
import type { WorkerRequest, WorkerResponse } from './kdfClient';

const ctx = self as unknown as DedicatedWorkerGlobalScope;

ctx.onmessage = async (ev: MessageEvent<WorkerRequest>) => {
  const msg = ev.data;
  let reply: WorkerResponse;
  try {
    switch (msg.op) {
      case 'derive':
        reply = { id: msg.id, ok: true, result: await deriveLoginKeys(msg.password, msg.kdfSalt, msg.kdfParams) };
        break;
      case 'register':
        reply = { id: msg.id, ok: true, result: await prepareRegistration(msg.email, msg.password) };
        break;
      case 'changePassword':
        reply = { id: msg.id, ok: true, result: await preparePasswordChange(msg.args) };
        break;
    }
  } catch (e) {
    reply = { id: msg.id, ok: false, error: e instanceof Error ? `${e.name}: ${e.message}` : 'Unknown error' };
  }
  ctx.postMessage(reply);
};
