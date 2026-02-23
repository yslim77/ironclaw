export type MonitoringAlertEmailConfig = {
  enabled?: boolean;
  to?: string;
  from?: string;
};

export type MonitoringAlertTelegramConfig = {
  enabled?: boolean;
  botToken?: string;
  chatId?: string;
};

export type MonitoringAlertSlackConfig = {
  enabled?: boolean;
  webhookUrl?: string;
  channel?: string;
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

export type MonitoringConfig = {
  enabled?: boolean;
  heartbeat?: MonitoringHeartbeatConfig;
  queue?: MonitoringQueueConfig;
  resources?: MonitoringResourceConfig;
  errorTracking?: MonitoringErrorTrackingConfig;
  alerts?: MonitoringAlertsConfig;
};
