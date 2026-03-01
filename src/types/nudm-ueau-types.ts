// 3GPP TS 29.503 version 17.12.0 Release 17
// Section 6.3.6
// https://www.etsi.org/deliver/etsi_ts/129500_129599/129503/17.12.00_60/ts_129503v171200p.pdf

import { PlmnId } from './common-types';

export type Autn = string;

export type Auts = string;

export type CkPrime = string;

export type IkPrime = string;

export type Kausf = string;

export type Rand = string;

export type ServingNetworkName = string;

export type Success = boolean;

export type Xres = string;

export type XresStar = string;

export type AuthenticatedInd = boolean;

export type ConfidentialityKey = string;

export type IntegrityKey = string;

export type Kasme = string;

export type NumOfRequestedVectors = number;

export enum AuthType {
  EAP_AKA_PRIME = "EAP_AKA_PRIME",
  FIVE_G_AKA = "5G_AKA",
  EAP_TLS = "EAP_TLS",
  NONE = "NONE",
  EAP_TTLS = "EAP_TTLS"
}

export enum AvType {
  FIVE_G_HE_AKA = "5G_HE_AKA",
  EAP_AKA_PRIME = "EAP_AKA_PRIME"
}

export enum HssAuthType {
  EPS_AKA = "EPS_AKA",
  EAP_AKA = "EAP_AKA",
  EAP_AKA_PRIME = "EAP_AKA_PRIME",
  IMS_AKA = "IMS_AKA",
  GBA_AKA = "GBA_AKA",
  UMTS_AKA = "UMTS_AKA"
}

export enum HssAvType {
  EPS_AKA = "EPS_AKA",
  EAP_AKA = "EAP_AKA",
  IMS_AKA = "IMS_AKA",
  GBA_AKA = "GBA_AKA",
  UMTS_AKA = "UMTS_AKA"
}

export enum HssAuthTypeInUri {
  EPS_AKA = "eps-aka",
  EAP_AKA = "eap-aka",
  EAP_AKA_PRIME = "eap-aka-prime",
  IMS_AKA = "ims-aka",
  GBA_AKA = "gba-aka",
  UMTS_AKA = "umts-aka"
}

export enum AccessNetworkId {
  HRPD = "HRPD",
  WIMAX = "WIMAX",
  WLAN = "WLAN",
  ETHERNET = "ETHERNET"
}

export enum NodeType {
  AUSF = "AUSF",
  VLR = "VLR",
  SGSN = "SGSN",
  S_CSCF = "S_CSCF",
  BSF = "BSF",
  GAN_AAA_SERVER = "GAN_AAA_SERVER",
  WLAN_AAA_SERVER = "WLAN_AAA_SERVER",
  MME = "MME"
}

export enum GbaAuthType {
  DIGEST_AKAV1_MD5 = "DIGEST_AKAV1_MD5"
}

export interface AuthenticationInfoRequest {
  servingNetworkName: ServingNetworkName;
  resynchronizationInfo?: ResynchronizationInfo;
  supportedFeatures?: string;
  ausfInstanceId: string;
  cellCagInfo?: string[];
  n5gcInd?: boolean;
  nswoInd?: boolean;
  disasterRoamingInd?: boolean;
}

export interface AuthenticationInfoResult {
  authType: AuthType;
  authenticationVector?: AuthenticationVector;
  supi?: string;
  akmaInd?: boolean;
  authAaa?: boolean;
  routingId?: string;
  pvsInfo?: ServerAddressingInfo[];
  supportedFeatures?: string;
}

export interface AvEapAkaPrime {
  avType: AvType;
  rand: Rand;
  xres: Xres;
  autn: Autn;
  ckPrime: CkPrime;
  ikPrime: IkPrime;
}

export interface Av5GHeAka {
  avType: AvType;
  rand: Rand;
  xresStar: XresStar;
  autn: Autn;
  kausf: Kausf;
}

export interface ResynchronizationInfo {
  rand: Rand;
  auts: Auts;
}

export interface AuthEvent {
  nfInstanceId: string;
  success: Success;
  timeStamp: string;
  authType: AuthType;
  servingNetworkName: ServingNetworkName;
  authRemovalInd?: boolean;
  nfSetId?: string;
  resetIds?: string[];
  dataRestorationCallbackUri?: string;
  udrRestartInd?: boolean;
  lastSynchronizationTime?: string;
  nswoInd?: boolean;
}

export type AuthenticationVector = AvEapAkaPrime | Av5GHeAka;

export interface RgAuthCtx {
  authInd: boolean;
  supi?: string;
  supportedFeatures?: string;
}

export interface HssAuthenticationInfoRequest {
  hssAuthType: HssAuthType;
  numOfRequestedVectors: NumOfRequestedVectors;
  requestingNodeType?: NodeType;
  servingNetworkId?: PlmnId;
  resynchronizationInfo?: ResynchronizationInfo;
  anId?: AccessNetworkId;
  supportedFeatures?: string;
}

export interface HssAuthenticationInfoResult {
  hssAuthenticationVectors: HssAuthenticationVectors;
  supportedFeatures?: string;
}

export type HssAuthenticationVectors = AvEpsAka[] | AvImsGbaEapAka[] | AvEapAkaPrime[];

export interface AvEpsAka {
  avType: HssAvType;
  rand: Rand;
  xres: Xres;
  autn: Autn;
  kasme: Kasme;
}

export interface AvImsGbaEapAka {
  avType: HssAvType;
  rand: Rand;
  xres: Xres;
  autn: Autn;
  ck: ConfidentialityKey;
  ik: IntegrityKey;
}

export interface GbaAuthenticationInfoRequest {
  authType: GbaAuthType;
  resynchronizationInfo?: ResynchronizationInfo;
  supportedFeatures?: string;
}

export interface GbaAuthenticationInfoResult {
  '3gAkaAv'?: ThreeGAkaAv;
  supportedFeatures?: string;
}

export interface ProSeAuthenticationInfoRequest {
  servingNetworkName: ServingNetworkName;
  relayServiceCode: string;
  resynchronizationInfo?: ResynchronizationInfo;
  supportedFeatures?: string;
}

export interface ProSeAuthenticationInfoResult {
  authType: AuthType;
  proseAuthenticationVectors?: ProSeAuthenticationVectors;
  supi?: string;
  supportedFeatures?: string;
}

export type ProSeAuthenticationVectors = AvEapAkaPrime[];

export interface ServerAddressingInfo {
  domainName?: string;
  ipv4Addresses?: string[];
  ipv6Addresses?: string[];
}

export interface ThreeGAkaAv {
  rand: Rand;
  xres: Xres;
  autn: Autn;
  ck: ConfidentialityKey;
  ik: IntegrityKey;
}
