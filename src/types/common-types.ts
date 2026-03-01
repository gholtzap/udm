export type Gpsi = string;

export type Supi = string;

export type Msisdn = string;

export type ExternalId = string;

export type UeIdentity = string;

export type Suci = string;

export type Dnn = string;

export type ReferenceId = number;

export interface PlmnId {
  mcc: string;
  mnc: string;
}

export interface Snssai {
  sst: number;
  sd?: string;
}

export enum RatType {
  NR = "NR",
  EUTRA = "EUTRA",
  WLAN = "WLAN",
  VIRTUAL = "VIRTUAL",
  NBIOT = "NBIOT",
  WIRELINE = "WIRELINE",
  WIRELINE_CABLE = "WIRELINE_CABLE",
  WIRELINE_BBF = "WIRELINE_BBF",
  LTE_M = "LTE-M",
  NR_U = "NR_U",
  EUTRA_U = "EUTRA_U",
  TRUSTED_N3GA = "TRUSTED_N3GA",
  TRUSTED_WLAN = "TRUSTED_WLAN",
  UTRA = "UTRA",
  GERA = "GERA",
  NR_LEO = "NR_LEO",
  NR_MEO = "NR_MEO",
  NR_GEO = "NR_GEO",
  NR_OTHER_SAT = "NR_OTHER_SAT"
}

export enum AccessType {
  THREE_GPP_ACCESS = "3GPP_ACCESS",
  NON_3GPP_ACCESS = "NON_3GPP_ACCESS",
  THREE_GPP_AND_NON_3GPP = "3GPP_AND_NON_3GPP"
}

export enum PduSessionType {
  IPV4 = "IPV4",
  IPV6 = "IPV6",
  IPV4V6 = "IPV4V6",
  UNSTRUCTURED = "UNSTRUCTURED",
  ETHERNET = "ETHERNET"
}

const UE_IDENTITY_PATTERNS = {
  msisdn: /^msisdn-[0-9]{5,15}$/,
  extid: /^extid-[^@]+@[^@]+$/,
  extgroupid: /^extgroupid-[^@]+@[^@]+$/,
  imsi: /^imsi-[0-9]{5,15}$/,
  nai: /^nai-.+$/,
  gci: /^gci-.+$/,
  gli: /^gli-.+$/,
  anyUE: /^anyUE$/
};

export const suciPattern = /^suci-\d+-\d+-\d+-\d+-\d+-\d+-[\dA-Fa-f]+$/;

export function validateUeIdentity(ueIdentity: string, allowedTypes?: (keyof typeof UE_IDENTITY_PATTERNS)[], allowCatchAll: boolean = false): boolean {
  if (!ueIdentity || ueIdentity.trim() === '') {
    return false;
  }

  const typesToCheck = allowedTypes || Object.keys(UE_IDENTITY_PATTERNS) as (keyof typeof UE_IDENTITY_PATTERNS)[];
  
  const matchesPattern = typesToCheck.some(type => {
    const pattern = UE_IDENTITY_PATTERNS[type];
    return pattern && pattern.test(ueIdentity);
  });

  if (matchesPattern) {
    return true;
  }

  if (allowCatchAll) {
    for (const type of typesToCheck) {
      const prefix = type + '-';
      if (ueIdentity.startsWith(prefix)) {
        return false;
      }
    }
    return true;
  }

  return false;
}

export function createInvalidParameterError(detail: string) {
  return {
    type: 'urn:3gpp:error:invalid-parameter',
    title: 'Bad Request',
    status: 400,
    detail,
    cause: 'INVALID_PARAMETER'
  };
}

export function createMissingParameterError(detail: string) {
  return {
    type: 'urn:3gpp:error:missing-parameter',
    title: 'Bad Request',
    status: 400,
    detail,
    cause: 'MANDATORY_IE_MISSING'
  };
}

export function createNotFoundError(detail: string) {
  return {
    type: 'urn:3gpp:error:not-found',
    title: 'Not Found',
    status: 404,
    detail,
    cause: 'DATA_NOT_FOUND'
  };
}

export interface ProblemDetails {
  type?: string;
  title: string;
  status: number;
  detail: string;
  cause?: string;
  retryAfter?: number;
}

export function createInternalError(detail: string) {
  return {
    type: 'urn:3gpp:error:internal-error',
    title: 'Internal Server Error',
    status: 500,
    detail,
    cause: 'SYSTEM_FAILURE'
  };
}

export function createNotImplementedError(detail: string) {
  return {
    type: 'urn:3gpp:error:not-implemented',
    title: 'Not Implemented',
    status: 501,
    detail
  };
}

export function createRateLimitError(detail: string, retryAfter: number) {
  return {
    type: 'urn:3gpp:error:too-many-requests',
    title: 'Too Many Requests',
    status: 429,
    detail,
    retryAfter
  };
}

export function createTimeoutError(detail: string) {
  return {
    type: 'urn:3gpp:error:request-timeout',
    title: 'Request Timeout',
    status: 408,
    detail
  };
}

export function createServiceUnavailableError(detail: string) {
  return {
    type: 'urn:3gpp:error:service-unavailable',
    title: 'Service Unavailable',
    status: 503,
    detail
  };
}

export function createAuthenticationRejectedError(detail: string) {
  return {
    type: 'urn:3gpp:error:authentication-rejected',
    title: 'Authentication Rejected',
    status: 403,
    detail
  };
}

export function createForbiddenError(detail: string, type?: string) {
  return {
    type: type || 'urn:3gpp:error:forbidden',
    title: 'Forbidden',
    status: 403,
    detail
  };
}

export function createUnprocessableError(detail: string) {
  return {
    type: 'urn:3gpp:error:application',
    title: 'Unprocessable Request',
    status: 422,
    detail
  };
}

export const extGroupIdPattern = /^[^@]+@[^@]+$/;

export function deepMerge(target: any, source: any): any {
  const result = { ...target };
  
  for (const key in source) {
    if (source[key] === null) {
      delete result[key];
    } else if (typeof source[key] === 'object' && !Array.isArray(source[key]) && source[key] !== null) {
      if (typeof result[key] === 'object' && !Array.isArray(result[key]) && result[key] !== null) {
        result[key] = deepMerge(result[key], source[key]);
      } else {
        result[key] = source[key];
      }
    } else {
      result[key] = source[key];
    }
  }
  
  return result;
}

export interface PatchItem {
  op: string;
  path: string;
  from?: string;
  value?: any;
}

export interface PatchResult {
  report: PatchItem[];
}