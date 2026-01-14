import { Router, Request, Response } from 'express';
import { getCollection } from '../db/mongodb';
import {
  ServiceSpecificAuthorizationInfo,
  ServiceSpecificAuthorizationData,
  ServiceSpecificAuthorizationRemoveData,
  ServiceType
} from '../types/nudm-ssau-types';
import { 
  validateUeIdentity, 
  createInvalidParameterError, 
  createMissingParameterError,
  Snssai,
  Supi,
  Gpsi
} from '../types/common-types';

const router = Router();

interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  cause: string;
}

interface SubscriptionData {
  _id: string;
  gpsis?: string[];
  externalIds?: string[];
  externalGroupIds?: string[];
  internalGroupId?: string;
  nssai?: {
    defaultSingleNssais?: Snssai[];
    singleNssais?: Snssai[];
  };
  subscribedSnssaiInfos?: Record<string, {
    dnnInfos?: Array<{
      dnn: string;
      defaultDnnIndicator?: boolean;
    }>;
  }>;
  allowedMtcProviders?: string[];
  allowedAfIds?: string[];
}

interface StoredAuthorizationData {
  _id: string;
  ueIdentity: string;
  serviceType: string;
  snssai?: Snssai;
  dnn?: string;
  mtcProviderInformation?: any;
  authUpdateCallbackUri?: string;
  afId?: string;
  nefId?: string;
  supi?: string;
  gpsi?: string;
  extGroupId?: string;
  intGroupId?: string;
  createdAt: Date;
}

function snssaiMatches(s1: Snssai, s2: Snssai): boolean {
  return s1.sst === s2.sst && s1.sd === s2.sd;
}

function getSnssaiKey(snssai: Snssai): string {
  return snssai.sd ? `${snssai.sst}-${snssai.sd}` : `${snssai.sst}`;
}

async function findUserByIdentity(ueIdentity: string): Promise<SubscriptionData | null> {
  const collection = getCollection<SubscriptionData>();
  
  if (ueIdentity.startsWith('msisdn-')) {
    return await collection.findOne({ gpsis: ueIdentity });
  } else if (ueIdentity.startsWith('extid-')) {
    return await collection.findOne({ externalIds: ueIdentity });
  } else if (ueIdentity.startsWith('extgroupid-')) {
    return await collection.findOne({ externalGroupIds: ueIdentity });
  }
  
  return null;
}

router.post('/:ueIdentity/:serviceType/authorize', async (req: Request<{ ueIdentity: string; serviceType: string }, any, ServiceSpecificAuthorizationInfo>, res: Response) => {
  const { ueIdentity, serviceType } = req.params;
  const body = req.body;

  if (!validateUeIdentity(ueIdentity, ['msisdn', 'extid', 'extgroupid'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueIdentity format') as any);
  }

  const validServiceTypes = Object.values(ServiceType);
  if (!validServiceTypes.includes(serviceType as ServiceType)) {
    return res.status(400).json(createInvalidParameterError('Invalid serviceType') as any);
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object') as any);
  }

  const { snssai, dnn, mtcProviderInformation, authUpdateCallbackUri, afId, nefId } = body;

  let userData: SubscriptionData | null;
  try {
    userData = await findUserByIdentity(ueIdentity);
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Database operation failed',
      cause: 'INTERNAL_ERROR'
    } as ProblemDetails);
  }

  if (!userData) {
    return res.status(404).json({
      type: 'urn:3gpp:error:user-not-found',
      title: 'Not Found',
      status: 404,
      detail: 'User not found',
      cause: 'USER_NOT_FOUND'
    } as ProblemDetails);
  }

  if (dnn) {
    let dnnAllowed = false;

    if (snssai && userData.subscribedSnssaiInfos) {
      const snssaiKey = getSnssaiKey(snssai);
      const snssaiInfo = userData.subscribedSnssaiInfos[snssaiKey];
      
      if (snssaiInfo?.dnnInfos) {
        dnnAllowed = snssaiInfo.dnnInfos.some(dnnInfo => dnnInfo.dnn === dnn);
      }
    }

    if (!dnnAllowed) {
      return res.status(403).json({
        type: 'urn:3gpp:error:dnn-not-allowed',
        title: 'Forbidden',
        status: 403,
        detail: 'DNN not allowed',
        cause: 'DNN_NOT_ALLOWED'
      } as ProblemDetails);
    }
  }

  if (snssai) {
    const allSnssais = [
      ...(userData.nssai?.defaultSingleNssais || []),
      ...(userData.nssai?.singleNssais || [])
    ];
    
    const snssaiAllowed = allSnssais.some(allowedSnssai => snssaiMatches(allowedSnssai, snssai));
    
    if (!snssaiAllowed) {
      return res.status(403).json({
        type: 'urn:3gpp:error:snssai-not-allowed',
        title: 'Forbidden',
        status: 403,
        detail: 'S-NSSAI not allowed',
        cause: 'SNSSAI_NOT_ALLOWED'
      } as ProblemDetails);
    }
  }

  if (mtcProviderInformation && userData.allowedMtcProviders) {
    const mtcProviderId = mtcProviderInformation.mtcProviderId || mtcProviderInformation.id;
    if (mtcProviderId && !userData.allowedMtcProviders.includes(mtcProviderId)) {
      return res.status(403).json({
        type: 'urn:3gpp:error:mtc-provider-not-allowed',
        title: 'Forbidden',
        status: 403,
        detail: 'MTC Provider not allowed',
        cause: 'MTC_PROVIDER_NOT_ALLOWED'
      } as ProblemDetails);
    }
  }

  if (afId && userData.allowedAfIds) {
    if (!userData.allowedAfIds.includes(afId)) {
      return res.status(403).json({
        type: 'urn:3gpp:error:af-instance-not-allowed',
        title: 'Forbidden',
        status: 403,
        detail: 'AF instance not allowed',
        cause: 'AF_INSTANCE_NOT_ALLOWED'
      } as ProblemDetails);
    }
  }

  const authId = `auth-${ueIdentity}-${serviceType}-${Date.now()}`;

  const authData: StoredAuthorizationData = {
    _id: authId,
    ueIdentity,
    serviceType,
    snssai,
    dnn,
    mtcProviderInformation,
    authUpdateCallbackUri,
    afId,
    nefId,
    supi: userData._id,
    createdAt: new Date()
  };

  if (ueIdentity.startsWith('msisdn-')) {
    authData.gpsi = ueIdentity;
  } else if (ueIdentity.startsWith('extid-')) {
    authData.gpsi = ueIdentity;
  } else if (ueIdentity.startsWith('extgroupid-')) {
    authData.extGroupId = ueIdentity;
    authData.intGroupId = userData.internalGroupId;
  }

  try {
    const authCollection = getCollection<StoredAuthorizationData>('ssau_authorizations');
    await authCollection.insertOne(authData);
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Failed to store authorization data',
      cause: 'INTERNAL_ERROR'
    } as ProblemDetails);
  }

  const response: ServiceSpecificAuthorizationData = {
    authId
  };

  if (authData.supi && authData.gpsi) {
    response.authorizationUeId = {
      supi: authData.supi as Supi,
      gpsi: authData.gpsi as Gpsi
    };
  } else if (authData.supi) {
    response.authorizationUeId = {
      supi: authData.supi as Supi
    };
  }

  if (authData.extGroupId) {
    response.extGroupId = authData.extGroupId;
  }

  if (authData.intGroupId) {
    response.IntGroupId = authData.intGroupId;
  }

  res.status(200).json(response);
});

router.post('/:ueIdentity/:serviceType/remove', async (req: Request<{ ueIdentity: string; serviceType: string }, any, ServiceSpecificAuthorizationRemoveData>, res: Response) => {
  const { ueIdentity, serviceType } = req.params;
  const body = req.body;

  if (!validateUeIdentity(ueIdentity, ['msisdn', 'extid', 'extgroupid'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueIdentity format') as any);
  }

  const validServiceTypes = Object.values(ServiceType);
  if (!validServiceTypes.includes(serviceType as ServiceType)) {
    return res.status(400).json(createInvalidParameterError('Invalid serviceType') as any);
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object') as any);
  }

  const { authId } = body;

  if (!authId) {
    return res.status(400).json(createMissingParameterError('Missing required field: authId') as any);
  }

  let authData: StoredAuthorizationData | null;
  try {
    const authCollection = getCollection<StoredAuthorizationData>('ssau_authorizations');
    authData = await authCollection.findOne({ _id: authId });
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Database operation failed',
      cause: 'INTERNAL_ERROR'
    } as ProblemDetails);
  }

  if (!authData) {
    return res.status(404).json({
      type: 'urn:3gpp:error:authorization-not-found',
      title: 'Not Found',
      status: 404,
      detail: 'Authorization not found',
      cause: 'AUTHORIZATION_NOT_FOUND'
    } as ProblemDetails);
  }

  if (authData.ueIdentity !== ueIdentity || authData.serviceType !== serviceType) {
    return res.status(404).json({
      type: 'urn:3gpp:error:authorization-not-found',
      title: 'Not Found',
      status: 404,
      detail: 'Authorization not found for the specified ueIdentity and serviceType',
      cause: 'AUTHORIZATION_NOT_FOUND'
    } as ProblemDetails);
  }

  try {
    const authCollection = getCollection<StoredAuthorizationData>('ssau_authorizations');
    await authCollection.deleteOne({ _id: authId });
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Failed to delete authorization data',
      cause: 'INTERNAL_ERROR'
    } as ProblemDetails);
  }

  res.status(204).send();
});

export default router;

