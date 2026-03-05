// 3GPP TS 29.503 version 17.12.0 Release 17
// Section 6.2.6
// https://www.etsi.org/deliver/etsi_ts/129500_129599/129503/17.12.00_60/ts_129503v171200p.pdf

import { PlmnId, Snssai, RatType, AccessType } from './common-types';

export type PurgeFlag = boolean;

export type E164Number = string;

export type DualRegistrationFlag = boolean;

export enum DeregistrationReason {
  UE_INITIAL_REGISTRATION = "UE_INITIAL_REGISTRATION",
  UE_REGISTRATION_AREA_CHANGE = "UE_REGISTRATION_AREA_CHANGE",
  SUBSCRIPTION_WITHDRAWN = "SUBSCRIPTION_WITHDRAWN",
  FIVE_GS_TO_EPS_MOBILITY = "5GS_TO_EPS_MOBILITY",
  FIVE_GS_TO_EPS_MOBILITY_UE_INITIAL_REGISTRATION = "5GS_TO_EPS_MOBILITY_UE_INITIAL_REGISTRATION",
  REREGISTRATION_REQUIRED = "REREGISTRATION_REQUIRED",
  SMF_CONTEXT_TRANSFERRED = "SMF_CONTEXT_TRANSFERRED",
  DUPLICATE_PDU_SESSION = "DUPLICATE_PDU_SESSION",
  PDU_SESSION_REACTIVATION_REQUIRED = "PDU_SESSION_REACTIVATION_REQUIRED",
  DISASTER_CONDITION_TERMINATED = "DISASTER_CONDITION_TERMINATED",
  OPERATOR_DETERMINED_BARRING = "OPERATOR_DETERMINED_BARRING",
  DUPLICATE_PDU_SESSION_EPDG = "DUPLICATE_PDU_SESSION_EPDG"
}

export enum ImsVoPs {
  HOMOGENEOUS_SUPPORT = "HOMOGENEOUS_SUPPORT",
  HOMOGENEOUS_NON_SUPPORT = "HOMOGENEOUS_NON_SUPPORT",
  NON_HOMOGENEOUS_OR_UNKNOWN = "NON_HOMOGENEOUS_OR_UNKNOWN"
}

export enum RegistrationReason {
  SMF_CONTEXT_TRANSFERRED = "SMF_CONTEXT_TRANSFERRED"
}

export enum RegistrationDataSetName {
  AMF_3GPP = "AMF_3GPP",
  AMF_NON_3GPP = "AMF_NON_3GPP",
  SMF_PDU_SESSIONS = "SMF_PDU_SESSIONS",
  SMSF_3GPP = "SMSF_3GPP",
  SMSF_NON_3GPP = "SMSF_NON_3GPP",
  IP_SM_GW = "IP_SM_GW",
  NWDAF = "NWDAF"
}

export enum UeReachableInd {
  REACHABLE = "REACHABLE",
  NOT_REACHABLE = "NOT_REACHABLE",
  UNKNOWN = "UNKNOWN"
}

export interface Amf3GppAccessRegistration {
  amfInstanceId: string;
  deregCallbackUri: string;
  guami: Guami;
  ratType: RatType;
  supportedFeatures?: string;
  purgeFlag?: PurgeFlag;
  pei?: string;
  imsVoPs?: ImsVoPs;
  amfServiceNameDereg?: string;
  pcscfRestorationCallbackUri?: string;
  amfServiceNamePcscfRest?: string;
  initialRegistrationInd?: boolean;
  emergencyRegistrationInd?: boolean;
  backupAmfInfo?: BackupAmfInfo[];
  drFlag?: DualRegistrationFlag;
  urrpIndicator?: boolean;
  amfEeSubscriptionId?: string;
  epsInterworkingInfo?: EpsInterworkingInfo;
  ueSrvccCapability?: boolean;
  registrationTime?: string;
  vgmlcAddress?: VgmlcAddress;
  contextInfo?: ContextInfo;
  noEeSubscriptionInd?: boolean;
  supi?: string;
  ueReachableInd?: UeReachableInd;
  reRegistrationRequired?: boolean;
  adminDeregSubWithdrawn?: boolean;
  dataRestorationCallbackUri?: string;
  resetIds?: string[];
  disasterRoamingInd?: boolean;
  ueMINTCapability?: boolean;
  sorSnpnSiSupported?: boolean;
  udrRestartInd?: boolean;
  lastSynchronizationTime?: string;
}

export interface AmfNon3GppAccessRegistration {
  amfInstanceId: string;
  deregCallbackUri: string;
  guami: Guami;
  ratType: RatType;
  supportedFeatures?: string;
  purgeFlag?: PurgeFlag;
  pei?: string;
  imsVoPs: ImsVoPs;
  amfServiceNameDereg?: string;
  pcscfRestorationCallbackUri?: string;
  amfServiceNamePcscfRest?: string;
  backupAmfInfo?: BackupAmfInfo[];
  urrpIndicator?: boolean;
  amfEeSubscriptionId?: string;
  registrationTime?: string;
  vgmlcAddress?: VgmlcAddress;
  contextInfo?: ContextInfo;
  noEeSubscriptionInd?: boolean;
  supi?: string;
  reRegistrationRequired?: boolean;
  adminDeregSubWithdrawn?: boolean;
  dataRestorationCallbackUri?: string;
  resetIds?: string[];
  disasterRoamingInd?: boolean;
  sorSnpnSiSupported?: boolean;
  udrRestartInd?: boolean;
  lastSynchronizationTime?: string;
}

export interface SmfRegistration {
  smfInstanceId: string;
  smfSetId?: string;
  supportedFeatures?: string;
  pduSessionId: number;
  singleNssai: Snssai;
  dnn?: string;
  emergencyServices?: boolean;
  pcscfRestorationCallbackUri?: string;
  plmnId: PlmnId;
  pgwFqdn?: string;
  pgwIpAddr?: IpAddress;
  epdgInd?: boolean;
  deregCallbackUri?: string;
  registrationReason?: RegistrationReason;
  registrationTime?: string;
  contextInfo?: ContextInfo;
  pcfId?: string;
  dataRestorationCallbackUri?: string;
  resetIds?: string[];
  udrRestartInd?: boolean;
  lastSynchronizationTime?: string;
}

export interface SmsfRegistration {
  smsfInstanceId: string;
  smsfSetId?: string;
  supportedFeatures?: string;
  plmnId: PlmnId;
  smsfMAPAddress?: E164Number;
  smsfDiameterAddress?: NetworkNodeDiameterAddress;
  registrationTime?: string;
  contextInfo?: ContextInfo;
  smsfSbiSupInd?: boolean;
  dataRestorationCallbackUri?: string;
  resetIds?: string[];
  udrRestartInd?: boolean;
  lastSynchronizationTime?: string;
  ueMemoryAvailableInd?: boolean;
}

export interface DeregistrationData {
  deregReason: DeregistrationReason;
  accessType?: AccessType;
  pduSessionId?: number;
  newSmfInstanceId?: string;
  oldGuami?: Guami;
}

export interface Amf3GppAccessRegistrationModification {
  guami: Guami;
  purgeFlag?: PurgeFlag;
  pei?: string;
  imsVoPs?: ImsVoPs;
  backupAmfInfo?: BackupAmfInfo[];
  epsInterworkingInfo?: EpsInterworkingInfo;
  ueSrvccCapability?: boolean;
  ueMINTCapability?: boolean;
}

export interface AmfNon3GppAccessRegistrationModification {
  guami: Guami;
  purgeFlag?: PurgeFlag;
  pei?: string;
  imsVoPs?: ImsVoPs;
  backupAmfInfo?: BackupAmfInfo[];
}

export interface PcscfRestorationNotification {
  supi: string;
  failedPcscf?: PcscfAddress;
}

export interface NetworkNodeDiameterAddress {
  name: string;
  realm: string;
}

export interface EpsIwkPgw {
  pgwFqdn: string;
  smfInstanceId: string;
  plmnId?: PlmnId;
}

export interface TriggerRequest {
  supi: string;
  failedPcscf?: PcscfAddress;
}

export interface AmfDeregInfo {
  deregReason: DeregistrationReason;
}

export interface EpsInterworkingInfo {
  epsIwkPgws?: Record<string, EpsIwkPgw>;
}

export interface LocationInfo {
  supi?: string;
  gpsi?: string;
  registrationLocationInfo: RegistrationLocationInfo[];
  supportedFeatures?: string;
}

export interface RegistrationLocationInfo {
  amfInstanceId: string;
  guami?: Guami;
  plmnId?: PlmnId;
  vgmlcAddress?: VgmlcAddress;
  accessTypeList: AccessType[];
}

export interface VgmlcAddress {
  vgmlcAddressIpv4?: string;
  vgmlcAddressIpv6?: string;
  vgmlcFqdn?: string;
}

export interface PeiUpdateInfo {
  pei: string;
}

export interface RegistrationDataSets {
  amf3Gpp?: Amf3GppAccessRegistration;
  amfNon3Gpp?: AmfNon3GppAccessRegistration;
  smfRegistration?: SmfRegistrationInfo;
  smsf3Gpp?: SmsfRegistration;
  smsfNon3Gpp?: SmsfRegistration;
  ipSmGw?: IpSmGwRegistration;
  nwdafRegistration?: NwdafRegistrationInfo;
}

export interface IpSmGwRegistration {
  ipSmGwMapAddress?: E164Number;
  ipSmGwDiameterAddress?: NetworkNodeDiameterAddress;
  ipsmgwIpv4?: string;
  ipsmgwIpv6?: string;
  ipsmgwFqdn?: string;
  ipSmGwSbiSupInd?: boolean;
  nfInstanceId?: string;
  unriIndicator?: boolean;
  resetIds?: string[];
}

export interface SmfRegistrationInfo {
  smfRegistrationList: SmfRegistration[];
}

export interface NwdafRegistration {
  nwdafInstanceId: string;
  analyticsIds: string[];
  nwdafSetId?: string;
  registrationTime?: string;
  contextInfo?: ContextInfo;
  supportedFeatures?: string;
  resetIds?: string[];
}

export interface NwdafRegistrationModification {
  nwdafInstanceId: string;
  nwdafSetId?: string;
  analyticsIds?: string[];
  supportedFeatures?: string;
}

export interface SmfRegistrationModification {
  smfInstanceId: string;
  smfSetId?: string;
  pgwFqdn?: string | null;
}

export interface SmsfRegistrationModification {
  smsfInstanceId: string;
  smsfSetId?: string;
  smsfMAPAddress?: E164Number | null;
  smsfDiameterAddress?: NetworkNodeDiameterAddress | null;
  smsfSbiSupInd?: boolean;
}

export interface RoamingInfoUpdate {
  servingPlmn: PlmnId;
  roaming?: boolean;
}

export interface DataRestorationNotification {
  lastReplicationTime?: string;
  recoveryTime?: string;
  plmnId?: PlmnId;
  supiRanges?: IdentityRange[];
  gpsiRanges?: SupiRange[];
  resetIds?: string[];
  sNssaiList?: Snssai[];
  dnnList?: string[];
  udmGroupId?: string;
}

export interface PcscfAddress {
  ipv4Addrs?: string[];
  ipv6Addrs?: string[];
  fqdn?: string;
}

export interface NwdafRegistrationInfo {
  nwdafRegistrationList: NwdafRegistration[];
}

export interface RoutingInfoSmRequest {
  ipSmGwInd?: boolean;
  correlationId?: string;
  supportedFeatures?: string;
}

export interface RoutingInfoSmResponse {
  supi?: string;
  smsf3Gpp?: SmsfRegistration;
  smsfNon3Gpp?: SmsfRegistration;
  ipSmGw?: IpSmGwInfo;
  smsRouter?: SmsRouterInfo;
  mpsMsgIndication?: boolean;
}

export interface IpSmGwInfo {
  ipSmGwRegistration: IpSmGwRegistration;
  ipSmGwGuidance?: IpSmGwGuidance;
}

export interface IpSmGwGuidance {
  minDeliveryTime: number;
  recommDeliveryTime: number;
}

export interface SmsRouterInfo {
  nfInstanceId?: string;
  diameterAddress?: NetworkNodeDiameterAddress;
  mapAddress?: E164Number;
  routerIpv4?: string;
  routerIpv6?: string;
  routerFqdn?: string;
}

export interface Guami {
  plmnId: PlmnId;
  amfId: string;
}

export interface BackupAmfInfo {
  backupAmf: string;
  guamiList?: Guami[];
}

export interface IpAddress {
  ipv4Addr?: string;
  ipv6Addr?: string;
}

export interface ContextInfo {
  [key: string]: any;
}

export interface IdentityRange {
  start?: string;
  end?: string;
  pattern?: string;
}

export interface SupiRange {
  start?: string;
  end?: string;
  pattern?: string;
}