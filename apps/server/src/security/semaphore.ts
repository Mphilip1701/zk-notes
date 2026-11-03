import { HttpError } from '../errors.js';

/**
 * Bounded concurrency with a bounded queue. Server-side Argon2 is deliberately
 * expensive; without this a burst of logins could pin every core / exhaust RAM.
 */
export class Semaphore {
  private active = 0;
  private readonly queue: (() => void)[] = [];

  constructor(
    private readonly max: number,
    private readonly maxQueue = 100,
  ) {}

  async run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.active >= this.max) {
      if (this.queue.length >= this.maxQueue) throw new HttpError(503, 'server_busy');
      await new Promise<void>((resolve) => this.queue.push(resolve));
    } else {
      this.active++;
    }
    try {
      return await fn();
    } finally {
      const next = this.queue.shift();
      if (next) next();
      else this.active--;
    }
  }
}
