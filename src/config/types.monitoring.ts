export type MonitoringAlertEmailConfig = {
  enabled?: boolean;
  to?: string;
  from?: string;
  subjectPrefix?: string;
  hookEnabled?: boolean;
  hookCommand?: string;
};

export type MonitoringAlertTelegramConfig = {
  enabled?: boolean;
  botToken?: string;
  chatId?: string;
  accountId?: string;
  hookEnabled?: boolean;
  hookCommand?: string;
};

export type MonitoringAlertSlackConfig = {
  enabled?: boolean;
  botToken?: string;
  webhookUrl?: string;
  channel?: string;
  accountId?: string;
  hookEnabled?: boolean;
  hookCommand?: string;
};

export type MonitoringAlertsConfig = {
  cooldownSeconds?: number;
  email?: MonitoringAlertEmailConfig;
  telegram?: MonitoringAlertTelegramConfig;
  slack?: MonitoringAlertSlackConfig;
};

export type MonitoringHeartbeatConfig = {
  enabled?: boolean;
  intervalSeconds?: number;
};

export type MonitoringQueueConfig = {
  enabled?: boolean;
  warnDepth?: number;
};

export type MonitoringResourceConfig = {
  enabled?: boolean;
  sampleSeconds?: number;
  maxRssMb?: number;
  maxHeapUsedMb?: number;
};

export type MonitoringErrorTrackingConfig = {
  enabled?: boolean;
};

export type MonitoringMetricsConfig = {
  enabled?: boolean;
  path?: string;
};

export type MonitoringConfig = {
  enabled?: boolean;
  heartbeat?: MonitoringHeartbeatConfig;
  queue?: MonitoringQueueConfig;
  resources?: MonitoringResourceConfig;
  errorTracking?: MonitoringErrorTrackingConfig;
  metrics?: MonitoringMetricsConfig;
  alerts?: MonitoringAlertsConfig;
};
