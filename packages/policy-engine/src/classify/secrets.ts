import { basenameOf, pathSegments } from '../paths.js';

export type SecretMatch = {
  category: string;
  label: string;
};

const SECRET_BASENAMES = new Set([
  '.env',
  '.env.local',
  '.env.development',
  '.env.production',
  '.env.staging',
  '.env.test',
  'credentials',
  'credentials.json',
  'service-account.json',
  'serviceAccount.json',
  'id_rsa',
  'id_ed25519',
  'id_ecdsa',
  'id_dsa',
  'authorized_keys',
  'known_hosts',
]);

const SECRET_EXTENSIONS = new Set([
  '.pem',
  '.key',
  '.p12',
  '.pfx',
  '.jks',
  '.kdbx',
]);

const SENSITIVE_DIR_SEGMENTS = new Set([
  '.aws',
  '.ssh',
  '.gnupg',
  '.kube',
  'secrets',
  'credentials',
  'private-keys',
  'private_keys',
]);

const SECRET_NAME_PATTERNS: readonly RegExp[] = [
  /^\.env(\..+)?$/i,
  /secret/i,
  /credential/i,
  /passwd/i,
  /password/i,
  /private[_-]?key/i,
  /^id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$/i,
  /service[_-]?account/i,
  /api[_-]?key/i,
  /access[_-]?key/i,
];

/**
 * Extensible secret classification — filename + path structure, not content sniffing.
 */
export function classifySecretPath(pathValue: string): SecretMatch | null {
  const base = basenameOf(pathValue);
  const segments = pathSegments(pathValue).map((s) => s.toLowerCase());
  const lowerBase = base.toLowerCase();

  if (SECRET_BASENAMES.has(lowerBase) || SECRET_BASENAMES.has(base)) {
    return { category: 'env_or_credential_file', label: base };
  }

  for (const pattern of SECRET_NAME_PATTERNS) {
    if (pattern.test(base)) {
      return { category: 'secret_name_pattern', label: base };
    }
  }

  const extMatch = lowerBase.match(/(\.[a-z0-9]+)$/);
  if (extMatch && SECRET_EXTENSIONS.has(extMatch[1]!)) {
    return { category: 'secret_extension', label: base };
  }

  for (const segment of segments) {
    if (SENSITIVE_DIR_SEGMENTS.has(segment)) {
      return { category: 'sensitive_directory', label: segment };
    }
  }

  if (segments.includes('.aws') && (lowerBase === 'credentials' || lowerBase === 'config')) {
    return { category: 'cloud_credentials', label: base };
  }

  return null;
}
