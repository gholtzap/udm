import { Router, Request, Response } from 'express';
import { AuthorizationInfo, AuthorizationData } from '../types/nudm-niddau-types';
import { validateUeIdentity, createInvalidParameterError, createMissingParameterError, Snssai } from '../types/common-types';
import { getCollection } from '../db/mongodb';

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
  snssai: Snssai;
  dnn: string;
  mtcProviderInformation: any;
  authUpdateCallbackUri: string;
  afId?: string;
  nefId?: string;
  validityTime?: string;
  contextInfo?: any;
  authData: AuthorizationData;
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

router.post('/:ueIdentity/authorize', async (req: Request<{ ueIdentity: string }, any, AuthorizationInfo>, res: Response) => {
  const { ueIdentity } = req.params;
  const body = req.body;

  if (!validateUeIdentity(ueIdentity, ['msisdn', 'extid', 'extgroupid'])) {
    return res.status(400).json(createInvalidParameterError('Invalid ueIdentity format') as any);
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object') as any);
  }

  const { snssai, dnn, mtcProviderInformation, authUpdateCallbackUri, afId, nefId, validityTime, contextInfo } = body;

  if (!snssai) {
    return res.status(400).json(createMissingParameterError('Missing required field: snssai') as any);
  }

  if (!dnn) {
    return res.status(400).json(createMissingParameterError('Missing required field: dnn') as any);
  }

  if (!mtcProviderInformation) {
    return res.status(400).json(createMissingParameterError('Missing required field: mtcProviderInformation') as any);
  }

  if (!authUpdateCallbackUri) {
    return res.status(400).json(createMissingParameterError('Missing required field: authUpdateCallbackUri') as any);
  }

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

  const allSnssais = [
    ...(userData.nssai?.defaultSingleNssais || []),
    ...(userData.nssai?.singleNssais || [])
  ];
  
  const snssaiAllowed = allSnssais.some(allowedSnssai => snssaiMatches(allowedSnssai, snssai));
  
  if (!snssaiAllowed) {
    return res.status(403).json({
      type: 'urn:3gpp:error:forbidden',
      title: 'Forbidden',
      status: 403,
      detail: 'S-NSSAI is not allowed for this user',
      cause: 'SNSSAI_NOT_ALLOWED'
    } as ProblemDetails);
  }

  const snssaiKey = getSnssaiKey(snssai);
  const snssaiInfo = userData.subscribedSnssaiInfos?.[snssaiKey];
  
  if (!snssaiInfo || !snssaiInfo.dnnInfos) {
    return res.status(403).json({
      type: 'urn:3gpp:error:forbidden',
      title: 'Forbidden',
      status: 403,
      detail: 'DNN is not allowed for this S-NSSAI',
      cause: 'DNN_NOT_ALLOWED'
    } as ProblemDetails);
  }
  
  const dnnAllowed = snssaiInfo.dnnInfos.some(dnnInfo => dnnInfo.dnn === dnn);
  
  if (!dnnAllowed) {
    return res.status(403).json({
      type: 'urn:3gpp:error:forbidden',
      title: 'Forbidden',
      status: 403,
      detail: 'DNN is not allowed for this user',
      cause: 'DNN_NOT_ALLOWED'
    } as ProblemDetails);
  }

  if (mtcProviderInformation) {
    const mtcProviderId = typeof mtcProviderInformation === 'object' 
      ? mtcProviderInformation.mtcProviderId 
      : mtcProviderInformation;
    
    if (mtcProviderId && userData.allowedMtcProviders && !userData.allowedMtcProviders.includes(mtcProviderId)) {
      return res.status(403).json({
        type: 'urn:3gpp:error:forbidden',
        title: 'Forbidden',
        status: 403,
        detail: 'MTC provider is not allowed for this user',
        cause: 'MTC_PROVIDER_NOT_ALLOWED'
      } as ProblemDetails);
    }
  }

  if (afId && userData.allowedAfIds && !userData.allowedAfIds.includes(afId)) {
    return res.status(403).json({
      type: 'urn:3gpp:error:forbidden',
      title: 'Forbidden',
      status: 403,
      detail: 'AF instance is not allowed for this user',
      cause: 'AF_INSTANCE_NOT_ALLOWED'
    } as ProblemDetails);
  }

  const supi = userData._id;
  const gpsi = ueIdentity.startsWith('msisdn-') ? ueIdentity : (userData.gpsis?.[0] || `msisdn-${supi.slice(-10)}`);

  const authData: AuthorizationData = {
    authorizationData: [
      {
        supi: supi,
        gpsi: gpsi,
        validityTime: validityTime || new Date(Date.now() + 86400000).toISOString()
      }
    ],
    validityTime: validityTime || new Date(Date.now() + 86400000).toISOString()
  };

  const storedData: StoredAuthorizationData = {
    _id: `${ueIdentity}:${Date.now()}`,
    ueIdentity,
    snssai,
    dnn,
    mtcProviderInformation,
    authUpdateCallbackUri,
    afId,
    nefId,
    validityTime,
    contextInfo,
    authData,
    createdAt: new Date()
  };

  try {
    const authCollection = getCollection<StoredAuthorizationData>('niddau-authorizations');
    await authCollection.insertOne(storedData);
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Failed to store authorization data',
      cause: 'INTERNAL_ERROR'
    } as ProblemDetails);
  }

  res.status(200).json(authData);
});

export default router;

