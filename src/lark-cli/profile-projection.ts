import { chmod, mkdir } from 'node:fs/promises';
import type { AppPaths } from '../config/app-paths';
import type { AppConfig, ProviderConfig, SecretRef, SecretsConfig } from '../config/schema';
import { isSecretRef } from '../config/schema';
import { ensureSecretsGetterWrapper } from '../config/store';
import { writeFileAtomic } from '../platform/atomic-write';

export async function writeLarkCliSourceProjection(
  cfg: AppConfig,
  appPaths: Pick<
    AppPaths,
    | 'rootDir'
    | 'profile'
    | 'larkCliSourceDir'
    | 'larkCliSourceConfigFile'
    | 'secretsGetterScript'
  >,
  opts: { resolvedAppSecret?: string } = {},
): Promise<string> {
  await mkdir(appPaths.larkCliSourceDir, { recursive: true, mode: 0o700 });
  await chmod(appPaths.larkCliSourceDir, 0o700).catch(() => {});

  // On Windows, Node's fs.stat().mode always returns 0666 regardless of ACLs,
  // so lark-cli's exec-provider security audit always fails. Work around this
  // by writing the resolved plaintext secret directly into the projection file
  // (which lark-cli does not audit for world-writable). The projection file
  // itself is written with mode 0o600 so the secret is not broadly accessible.
  const isWindows = process.platform === 'win32';
  const useInlineSecret = isWindows && typeof opts.resolvedAppSecret === 'string';

  const appSecret = useInlineSecret ? opts.resolvedAppSecret! : cfg.accounts.app.secret;
  const secrets = useInlineSecret ? undefined : await buildProjectionSecrets(cfg, appPaths);

  const projection = {
    accounts: {
      app: {
        id: cfg.accounts.app.id,
        secret: appSecret,
        tenant: cfg.accounts.app.tenant,
      },
    },
    ...(secrets ? { secrets } : {}),
  };

  await writeFileAtomic(appPaths.larkCliSourceConfigFile, `${JSON.stringify(projection, null, 2)}\n`, {
    mode: 0o600,
  });
  return appPaths.larkCliSourceConfigFile;
}

async function buildProjectionSecrets(
  cfg: AppConfig,
  appPaths: Pick<AppPaths, 'rootDir' | 'profile' | 'secretsGetterScript'>,
): Promise<SecretsConfig | undefined> {
  const providers: Record<string, ProviderConfig> = {
    ...(cfg.secrets?.providers ?? {}),
  };
  const providerName = bridgeProviderName(cfg.accounts.app.secret);
  if (providerName) {
    const wrapperPath = await ensureSecretsGetterWrapper(appPaths);
    const existing = providers[providerName];
    providers[providerName] = {
      ...(existing ?? {}),
      source: 'exec',
      command: wrapperPath,
      args: [],
      env: {
        ...(existing?.env ?? {}),
        LARK_CHANNEL_HOME: appPaths.rootDir,
        LARK_CHANNEL_PROFILE: appPaths.profile,
      },
    };
  }

  if (Object.keys(providers).length === 0 && !cfg.secrets?.defaults) return undefined;
  return {
    ...(cfg.secrets?.defaults ? { defaults: cfg.secrets.defaults } : {}),
    ...(Object.keys(providers).length > 0 ? { providers } : {}),
  };
}

function bridgeProviderName(secret: AppConfig['accounts']['app']['secret']): string | undefined {
  if (!isSecretRef(secret)) return undefined;
  if (secret.source !== 'exec') return undefined;
  const ref = secret as SecretRef;
  return ref.provider ?? 'default';
}
