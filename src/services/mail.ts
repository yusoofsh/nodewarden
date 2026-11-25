import type { Env } from '../types';
import { normalizeBackupEndpointUrl } from './backup-config';

// Outbound mail. A message goes to Resend (RESEND_API_KEY), to a webhook relay
// (MAIL_WEBHOOK_URL) that receives {from, to, subject, text, html} as JSON, or to
// Cloudflare Email Sending through the EMAIL send_email binding, in that order.
// Mail is off unless MAIL_FROM and one provider are set; every mail-backed route then
// answers as it did before mail existed.
// Never log message bodies, codes or credentials.

export type MailProvider =
  | { kind: 'resend'; apiKey: string }
  | { kind: 'webhook'; url: string; token: string | null }
  | { kind: 'cloudflare'; binding: SendEmail };

export interface MailConfig {
  from: string;
  provider: MailProvider;
}

export interface MailMessage {
  to: string;
  subject: string;
  text: string;
}

const RESEND_URL = 'https://api.resend.com/emails';
const SEND_TIMEOUT_MS = 10_000;

// The webhook must be public https: the backup endpoint rules refuse loopback, private,
// link-local and metadata hosts, and this adds the https requirement on top.
export function normalizeMailWebhookUrl(value: string): string | null {
  try {
    const url = normalizeBackupEndpointUrl(value.trim(), 'MAIL_WEBHOOK_URL');
    return url.startsWith('https://') ? url : null;
  } catch {
    return null;
  }
}

export function mailConfig(env: Env): MailConfig | null {
  const from = (env.MAIL_FROM || '').trim();
  if (!from) return null;
  const apiKey = (env.RESEND_API_KEY || '').trim();
  if (apiKey) return { from, provider: { kind: 'resend', apiKey } };
  const rawUrl = (env.MAIL_WEBHOOK_URL || '').trim();
  if (!rawUrl) return env.EMAIL ? { from, provider: { kind: 'cloudflare', binding: env.EMAIL } } : null;
  const url = normalizeMailWebhookUrl(rawUrl);
  if (!url) {
    console.warn('Mail disabled: MAIL_WEBHOOK_URL must be a public https URL');
    return null;
  }
  return { from, provider: { kind: 'webhook', url, token: (env.MAIL_WEBHOOK_TOKEN || '').trim() || null } };
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function textToHtml(text: string): string {
  const body = escapeHtml(text)
    .replace(/https?:\/\/[^\s<]*[^\s<.,]/g, (url) => `<a href="${url}">${url}</a>`)
    .replace(/\n/g, '<br>\n');
  return `<!doctype html><html><body><p>${body}</p></body></html>`;
}

// The binding takes a bare address or {email, name}; MAIL_FROM may be "Name <address>".
export function bindingSender(from: string): string | EmailAddress {
  const match = /^\s*"?([^"<]*?)"?\s*<([^<>\s]+)>\s*$/.exec(from);
  if (!match) return from;
  return match[1] ? { email: match[2], name: match[1] } : match[2];
}

// Returns whether the provider accepted the message.
export async function sendMail(config: MailConfig, message: MailMessage): Promise<boolean> {
  // No line breaks in headers: a relay may turn the subject into an SMTP header.
  const subject = message.subject.replace(/[\r\n]+/g, ' ');
  const payload = { from: config.from, to: message.to, subject, text: message.text, html: textToHtml(message.text) };
  const { provider } = config;
  if (provider.kind === 'cloudflare') {
    try {
      await provider.binding.send({ ...payload, from: bindingSender(config.from) });
      return true;
    } catch (error) {
      // E_RECIPIENT_PLAN_RESTRICTED here means a Workers Free account and an unverified recipient.
      const code = (error as { code?: unknown } | null)?.code;
      console.warn('Mail provider refused a message', { provider: provider.kind, code: typeof code === 'string' ? code : 'unknown' });
      return false;
    }
  }
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (provider.kind === 'resend') headers.Authorization = `Bearer ${provider.apiKey}`;
  else if (provider.token) headers.Authorization = `Bearer ${provider.token}`;
  try {
    const response = await fetch(provider.kind === 'resend' ? RESEND_URL : provider.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(provider.kind === 'resend' ? { ...payload, to: [message.to] } : payload),
      redirect: 'manual',
      signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
    });
    await response.body?.cancel();
    if (response.ok) return true;
    console.warn('Mail provider refused a message', { provider: provider.kind, status: response.status });
  } catch (error) {
    console.warn('Mail provider unreachable', { provider: provider.kind, error: error instanceof Error ? error.name : 'unknown' });
  }
  return false;
}

// Plain English templates. `origin` is the server's own URL, taken from the request.
const footer = (origin: string) => `\n\nThis message was sent by the password manager at ${origin}.`;
const codeText = (lead: string, code: string, origin: string) =>
  `${lead}\n\n${code}\n\nThe code expires in 10 minutes. If you did not request it, ignore this email.${footer(origin)}`;

export const mailTemplates = {
  twoFactorCode: (to: string, code: string, origin: string): MailMessage => ({
    to,
    subject: 'Your two-step login code',
    text: codeText('Your two-step login verification code is:', code, origin),
  }),
  changeEmailCode: (to: string, code: string, origin: string): MailMessage => ({
    to,
    subject: 'Confirm your new email address',
    text: codeText('Enter this code to finish changing your account email to this address:', code, origin),
  }),
  protectedActionCode: (to: string, code: string, origin: string): MailMessage => ({
    to,
    subject: 'Your verification code',
    text: codeText('Your verification code is:', code, origin),
  }),
  verifyEmail: (to: string, link: string, origin: string): MailMessage => ({
    to,
    subject: 'Verify your email address',
    text: `Open this link to verify the email address of your account:\n\n${link}\n\nThe link expires in 24 hours.${footer(origin)}`,
  }),
  deleteAccount: (to: string, link: string, origin: string): MailMessage => ({
    to,
    subject: 'Delete your account',
    text:
      `Someone asked to delete the account for this email address. Open this link to delete it and all its data:\n\n${link}\n\n` +
      `The link expires in 24 hours. If you did not ask for this, ignore this email; nothing changes.${footer(origin)}`,
  }),
  registerVerify: (to: string, link: string, origin: string): MailMessage => ({
    to,
    subject: 'Finish creating your account',
    text: `Open this link to verify your email address and finish creating your account:\n\n${link}\n\nThe link expires in 24 hours.${footer(origin)}`,
  }),
  emergencyAccessInvite: (to: string, grantor: string, origin: string): MailMessage => ({
    to,
    subject: 'You have been added as an emergency contact',
    text: `${grantor} added you as an emergency contact. Log in at ${origin} to see it under emergency access.${footer(origin)}`,
  }),
};
