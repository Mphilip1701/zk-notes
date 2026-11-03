import argon2 from 'argon2';
import { randomBytes } from 'node:crypto';
import { Semaphore } from './semaphore.js';

/**
 * Server-side Argon2id over the client's auth key (AK). AK is already the output
 * of a 64 MiB Argon2id + HKDF, so this second layer mainly ensures a DB leak does
 * not hand out AKs that can be replayed to log in. OWASP minimum params.
 */
export const SERVER_ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19 * 1024,
  timeCost: 2,
  parallelism: 1,
} as const;

export class AuthHasher {
  private readonly sem: Semaphore;
  private dummyHash: Promise<string> | undefined;

  constructor(maxConcurrency: number) {
    this.sem = new Semaphore(maxConcurrency);
  }

  hash(authKey: Buffer): Promise<string> {
    return this.sem.run(() => argon2.hash(authKey, SERVER_ARGON2_OPTIONS));
  }

  /** Returns false (never throws) on mismatch or malformed hash. */
  verify(storedHash: string, authKey: Buffer): Promise<boolean> {
    return this.sem.run(async () => {
      try {
        return await argon2.verify(storedHash, authKey);
      } catch {
        return false;
      }
    });
  }

  needsRehash(storedHash: string): boolean {
    return argon2.needsRehash(storedHash, SERVER_ARGON2_OPTIONS);
  }

  /**
   * For unknown accounts: spend the same work as a real verification so
   * response timing does not reveal whether the email is registered.
   */
  async verifyDummy(authKey: Buffer): Promise<false> {
    this.dummyHash ??= argon2.hash(randomBytes(32), SERVER_ARGON2_OPTIONS);
    await this.verify(await this.dummyHash, authKey);
    return false;
  }
}
