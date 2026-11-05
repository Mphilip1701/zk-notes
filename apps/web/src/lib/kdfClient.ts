import type {
  PasswordChangeRequest,
  RecoveryResetRequest,
  RecoverySetupRequest,
  RegistrationRequest,
  prepareRecoveryReset,
  prepareRecoverySetup,
  preparePasswordChange,
} from '@zk-notes/crypto';

type ChangeArgs = Parameters<typeof preparePasswordChange>[0];
type RecoverySetupArgs = Parameters<typeof prepareRecoverySetup>[0];
type RecoveryResetArgs = Parameters<typeof prepareRecoveryReset>[0];

export type WorkerRequest =
  | { id: number; op: 'derive'; password: string; kdfSalt: string; kdfParams: unknown }
  | { id: number; op: 'register'; email: string; password: string }
  | { id: number; op: 'changePassword'; args: ChangeArgs }
  | { id: number; op: 'recoverySetup'; args: RecoverySetupArgs }
  | { id: number; op: 'recoveryReset'; args: RecoveryResetArgs };

export type WorkerResponse = { id: number; ok: true; result: unknown } | { id: number; ok: false; error: string };

let worker: Worker | undefined;
let nextId = 1;
const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();

function getWorker(): Worker {
  if (!worker) {
    worker = new Worker(new URL('./kdf.worker.ts', import.meta.url), { type: 'module' });
    worker.onmessage = (ev: MessageEvent<WorkerResponse>) => {
      const p = pending.get(ev.data.id);
      if (!p) return;
      pending.delete(ev.data.id);
      if (ev.data.ok) p.resolve(ev.data.result);
      else p.reject(new Error(ev.data.error));
    };
    worker.onerror = (ev) => {
      for (const p of pending.values()) p.reject(new Error(ev.message || 'KDF worker failed'));
      pending.clear();
      worker = undefined;
    };
  }
  return worker;
}

type Distribute<T> = T extends unknown ? Omit<T, 'id'> : never;

function run<T>(req: Distribute<WorkerRequest>): Promise<T> {
  const id = nextId++;
  return new Promise<T>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (v: unknown) => void, reject });
    getWorker().postMessage({ ...req, id });
  });
}

export const kdf = {
  derive: (password: string, kdfSalt: string, kdfParams: unknown) =>
    run<{ authKey: string; kek: CryptoKey }>({ op: 'derive', password, kdfSalt, kdfParams }),
  register: (email: string, password: string) =>
    run<{ request: RegistrationRequest; vaultKey: CryptoKey }>({ op: 'register', email, password }),
  changePassword: (args: ChangeArgs) => run<PasswordChangeRequest>({ op: 'changePassword', args }),
  recoverySetup: (args: RecoverySetupArgs) =>
    run<{ request: RecoverySetupRequest; recoveryKey: string }>({ op: 'recoverySetup', args }),
  /** The recovery KEK is a non-extractable CryptoKey; structured clone carries it into the worker. */
  recoveryReset: (args: RecoveryResetArgs) =>
    run<{ request: RecoveryResetRequest; vaultKey: CryptoKey }>({ op: 'recoveryReset', args }),
};
