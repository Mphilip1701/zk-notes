import { ApiError } from './api';

/** Map errors to user-facing text without leaking internals. */
export function describeError(e: unknown): string {
  if (e instanceof ApiError) {
    switch (e.code) {
      case 'invalid_credentials':
        return 'Incorrect email or password.';
      case 'rate_limited':
        return 'Too many attempts. Please wait a few minutes and try again.';
      case 'registration_failed':
        return 'Could not create an account with that email.';
      case 'version_conflict':
        return 'This note was changed on another device. Reload to get the latest version.';
      case 'unauthenticated':
        return 'Your session expired. Please sign in again.';
      case 'recovery_key_changed':
        return 'The recovery key was changed while you were recovering. Try again with the current key.';
      case 'server_busy':
        return 'The server is busy. Please try again shortly.';
      default:
        return `Request failed (${e.status}).`;
    }
  }
  // Errors thrown in the main thread keep their name; errors from the KDF worker
  // arrive as "Name: message" strings.
  const is = (name: string) => e instanceof Error && (e.name === name || e.message.startsWith(`${name}:`));
  if (is('DecryptionError')) return 'Incorrect password.';
  if (is('CryptoInputError')) {
    return 'The server sent unsafe or invalid key parameters. Refusing to continue.';
  }
  return 'Something went wrong.';
}
