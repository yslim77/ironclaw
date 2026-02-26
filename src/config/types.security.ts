export type SecretResolverProvider = "env" | "keychain" | "1password";

export type SecuritySecretsConfig = {
  enabled?: boolean;
  preferredProvider?: SecretResolverProvider;
  providers?: {
    env?: { enabled?: boolean };
    keychain?: {
      enabled?: boolean;
      service?: string;
      account?: string;
      command?: string;
    };
    onePassword?: {
      enabled?: boolean;
      vault?: string;
      account?: string;
      command?: string;
    };
  };
  placeholders?: {
    envPrefix?: string;
    keychainPrefix?: string;
    onePasswordPrefix?: string;
  };
};

export type SecurityAuditConfig = {
  enabled?: boolean;
  file?: string;
  includePayloads?: boolean;
};

export type SecurityScopedTokenConfig = {
  enabled?: boolean;
  token?: string;
  scopes?: string[];
  expiresAt?: string;
  description?: string;
};

export type SecurityRbacConfig = {
  enabled?: boolean;
  scopedTokens?: Record<string, SecurityScopedTokenConfig>;
};

export type SecurityRateLimitRuleConfig = {
  maxRequests?: number;
  windowMs?: number;
};

export type SecurityRateLimitConfig = {
  enabled?: boolean;
  default?: SecurityRateLimitRuleConfig;
  byScope?: Record<string, SecurityRateLimitRuleConfig>;
};

export type SecuritySandboxGateConfig = {
  enabled?: boolean;
  defaultPolicy?: "allow" | "deny";
  allowedTools?: string[];
  deniedTools?: string[];
  allowedPaths?: string[];
  deniedPaths?: string[];
};

export type SecurityFrameworkConfig = {
  secrets?: SecuritySecretsConfig;
  audit?: SecurityAuditConfig;
  rbac?: SecurityRbacConfig;
  rateLimit?: SecurityRateLimitConfig;
  sandbox?: SecuritySandboxGateConfig;
};
