import { Router, Request, Response } from 'express';
import { getCollection } from '../db/mongodb';
import {
  AuthenticationInfoRequest,
  AuthenticationInfoResult,
  AuthType,
  AvType,
  Av5GHeAka,
  RgAuthCtx,
  AuthEvent,
  HssAuthenticationInfoRequest,
  HssAuthenticationInfoResult,
  HssAuthType,
  HssAvType,
  HssAuthTypeInUri,
  AvEpsAka,
  AvImsGbaEapAka,
  AvEapAkaPrime,
  AuthenticationVector,
  GbaAuthenticationInfoRequest,
  GbaAuthenticationInfoResult,
  GbaAuthType,
  ThreeGAkaAv,
  ProSeAuthenticationInfoRequest,
  ProSeAuthenticationInfoResult
} from '../types/nudm-ueau-types';
import { createNotFoundError, createInvalidParameterError, createMissingParameterError, createNotImplementedError, createInternalError, createAuthenticationRejectedError, suciPattern, PlmnId, validateUeIdentity, deconcealSuci } from '../types/common-types';
import {
  generateRand,
  milenage,
  MilenageOutput,
  computeKausf,
  computeXresStar,
  computeCkPrimeIkPrime,
  computeKasme,
  processAuts
} from '../utils/auth-crypto';
import { randomUUID } from 'crypto';
import { auditLog } from '../utils/logger';

const router = Router();

interface SubscriberData {
  _id?: string;
  supi: string;
  permanentKey: string;
  operatorKey: string;
  sequenceNumber: string;
  authenticationMethod: string;
  subscribedData?: {
    authenticationSubscription?: {
      authenticationMethod: string;
      permanentKey?: {
        permanentKeyValue: string;
      };
      sequenceNumber?: string;
      authenticationManagementField?: string;
      milenage?: {
        op?: {
          opValue: string;
        };
      };
    };
  };
}

router.post('/:supiOrSuci/security-information/generate-auth-data', async (req: Request, res: Response) => {
  const { supiOrSuci } = req.params;
  const authRequest: AuthenticationInfoRequest = req.body;

  auditLog('auth_vector_generation_request', {
    identifier_type: suciPattern.test(supiOrSuci) ? 'suci' : 'supi',
    serving_network: authRequest?.servingNetworkName,
    ausf_instance: authRequest?.ausfInstanceId
  }, 'Received authentication vector generation request');

  if (!authRequest || typeof authRequest !== 'object') {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  if (!authRequest.servingNetworkName) {
    return res.status(400).json(createInvalidParameterError('servingNetworkName is required'));
  }

  if (!authRequest.ausfInstanceId) {
    return res.status(400).json(createInvalidParameterError('ausfInstanceId is required'));
  }

  let supi = supiOrSuci;

  if (suciPattern.test(supiOrSuci)) {
    const result = deconcealSuci(supiOrSuci);
    if ('error' in result) {
      return res.status(501).json(createNotImplementedError(result.error));
    }
    supi = result.supi;
  }

  if (!supi.startsWith('imsi-')) {
    return res.status(400).json(createInvalidParameterError('Invalid SUPI format, must start with imsi-'));
  }

  let subscriber: SubscriberData | null;
  try {
    const subscribersCollection = getCollection<SubscriberData>('subscribers');
    subscriber = await subscribersCollection.findOne({ supi });
  } catch (error) {
    auditLog('auth_vector_generation_failed', {
      supi: supi,
      reason: 'database_error',
      error: error instanceof Error ? error.message : String(error)
    }, 'Auth vector generation failed: Database error');
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Database operation failed'
    });
  }

  if (!subscriber) {
    auditLog('auth_vector_generation_failed', {
      supi: supi,
      reason: 'subscriber_not_found'
    }, 'Auth vector generation failed: Subscriber not found');
    return res.status(404).json(createNotFoundError(`Subscriber with SUPI ${supi} not found`));
  }

  let permanentKey: string;
  let operatorKey: string;
  let sequenceNumber: string;
  let amf = '8000';

  if (subscriber.subscribedData?.authenticationSubscription) {
    const authSub = subscriber.subscribedData.authenticationSubscription;
    permanentKey = authSub.permanentKey?.permanentKeyValue || subscriber.permanentKey;
    operatorKey = authSub.milenage?.op?.opValue || subscriber.operatorKey;
    sequenceNumber = authSub.sequenceNumber || subscriber.sequenceNumber;
    amf = authSub.authenticationManagementField || '8000';
  } else {
    permanentKey = subscriber.permanentKey;
    operatorKey = subscriber.operatorKey;
    sequenceNumber = subscriber.sequenceNumber;
  }

  const authMethod = subscriber.subscribedData?.authenticationSubscription?.authenticationMethod
    || subscriber.authenticationMethod
    || '5G_AKA';

  if (authMethod !== '5G_AKA' && authMethod !== 'EAP_AKA_PRIME') {
    return res.status(400).json(createInvalidParameterError(`Unsupported authentication method: ${authMethod}`));
  }

  if (!permanentKey || !operatorKey || !sequenceNumber) {
    auditLog('auth_vector_generation_failed', {
      supi: supi,
      reason: 'missing_credentials'
    }, 'Auth vector generation failed: Missing authentication credentials');
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Missing authentication credentials for subscriber'
    });
  }

  const credHexPattern = /^[0-9A-Fa-f]+$/;
  if (!credHexPattern.test(permanentKey) || permanentKey.length !== 32) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Invalid permanentKey format in subscriber data'
    });
  }
  if (!credHexPattern.test(operatorKey) || operatorKey.length !== 32) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Invalid operatorKey format in subscriber data'
    });
  }
  if (!credHexPattern.test(sequenceNumber) || sequenceNumber.length !== 12) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Invalid sequenceNumber format in subscriber data'
    });
  }

  auditLog('key_access', {
    supi: supi,
    key_types: ['permanentKey', 'operatorKey'],
    purpose: 'auth_vector_generation'
  }, 'Accessed subscriber cryptographic keys for authentication');

  if (authRequest.resynchronizationInfo) {
    const hexPattern = /^[0-9A-Fa-f]+$/;
    const resyncRand = authRequest.resynchronizationInfo.rand;
    const resyncAuts = authRequest.resynchronizationInfo.auts;

    if (!resyncRand || !hexPattern.test(resyncRand) || resyncRand.length !== 32) {
      return res.status(400).json(createInvalidParameterError('resynchronizationInfo.rand must be exactly 32 hex characters'));
    }
    if (!resyncAuts || !hexPattern.test(resyncAuts) || resyncAuts.length !== 28) {
      return res.status(400).json(createInvalidParameterError('resynchronizationInfo.auts must be exactly 28 hex characters'));
    }

    auditLog('resynchronization_request', {
      supi: supi,
      rand: resyncRand
    }, 'Sequence number resynchronization requested');
    const kBuf = Buffer.from(permanentKey, 'hex');
    const opBuf = Buffer.from(operatorKey, 'hex');
    const randBuf = Buffer.from(resyncRand, 'hex');
    const autsBuf = Buffer.from(resyncAuts, 'hex');
    const amfBuf = Buffer.from(amf, 'hex');

    const sqnMs = processAuts(kBuf, opBuf, randBuf, autsBuf, amfBuf);

    if (!sqnMs) {
      auditLog('resynchronization_failed', {
        supi: supi,
        reason: 'auts_validation_failed'
      }, 'Resynchronization failed: AUTS validation failed');
      return res.status(403).json({
        type: 'urn:3gpp:error:authentication-rejected',
        title: 'Authentication Rejected',
        status: 403,
        detail: 'AUTS validation failed'
      });
    }

    const sqnMsInt = parseInt(sqnMs, 16);
    const newSqnInt = (sqnMsInt + 32) & 0xFFFFFFFFFFFF;
    sequenceNumber = newSqnInt.toString(16).padStart(12, '0').toUpperCase();

    try {
      const subscribersCollection = getCollection<SubscriberData>('subscribers');
      let updateResult;
      if (subscriber.subscribedData?.authenticationSubscription) {
        updateResult = await subscribersCollection.updateOne(
          { supi },
          { $set: { 'subscribedData.authenticationSubscription.sequenceNumber': sequenceNumber } }
        );
      } else {
        updateResult = await subscribersCollection.updateOne(
          { supi },
          { $set: { sequenceNumber: sequenceNumber } }
        );
      }

      if (updateResult.matchedCount === 0) {
        auditLog('resynchronization_failed', {
          supi: supi,
          reason: 'database_update_failed'
        }, 'Resynchronization failed: Failed to persist new SQN');
        return res.status(500).json({
          type: 'urn:3gpp:error:internal-error',
          title: 'Internal Server Error',
          status: 500,
          detail: 'Failed to persist resynchronized sequence number'
        });
      }
    } catch (error) {
      auditLog('resynchronization_failed', {
        supi: supi,
        reason: 'database_error',
        error: error instanceof Error ? error.message : String(error)
      }, 'Resynchronization failed: Database error');
      return res.status(500).json({
        type: 'urn:3gpp:error:internal-error',
        title: 'Internal Server Error',
        status: 500,
        detail: 'Failed to persist resynchronized sequence number'
      });
    }

    auditLog('resynchronization_success', {
      supi: supi,
      new_sequence_number: sequenceNumber
    }, 'Sequence number resynchronization completed successfully');
  }

  const rand = generateRand();
  const randBuf = Buffer.from(rand, 'hex');
  const kBuf = Buffer.from(permanentKey, 'hex');
  const opBuf = Buffer.from(operatorKey, 'hex');
  const sqnBuf = Buffer.from(sequenceNumber, 'hex');
  const amfBuf = Buffer.from(amf, 'hex');

  const milenageOutput = milenage(kBuf, opBuf, randBuf, sqnBuf, amfBuf);

  const sqnXorAk = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) {
    sqnXorAk[i] = sqnBuf[i] ^ milenageOutput.ak[i];
  }

  const autn = Buffer.concat([sqnXorAk, amfBuf, milenageOutput.mac_a]).toString('hex').toUpperCase();

  let authVector: AuthenticationVector;
  let authType: AuthType;

  if (authMethod === 'EAP_AKA_PRIME') {
    const { ckPrime, ikPrime } = computeCkPrimeIkPrime(
      milenageOutput.ck,
      milenageOutput.ik,
      authRequest.servingNetworkName,
      sqnXorAk
    );

    authVector = {
      avType: AvType.EAP_AKA_PRIME,
      rand: rand,
      xres: milenageOutput.res.toString('hex').toUpperCase(),
      autn: autn,
      ckPrime: ckPrime,
      ikPrime: ikPrime
    } as AvEapAkaPrime;
    authType = AuthType.EAP_AKA_PRIME;
  } else {
    const kausf = computeKausf(
      milenageOutput.ck,
      milenageOutput.ik,
      authRequest.servingNetworkName,
      sqnXorAk
    );

    const xresStar = computeXresStar(
      milenageOutput.res,
      randBuf,
      authRequest.servingNetworkName,
      milenageOutput.ck,
      milenageOutput.ik
    );

    authVector = {
      avType: AvType.FIVE_G_HE_AKA,
      rand: rand,
      xresStar: xresStar,
      autn: autn,
      kausf: kausf
    } as Av5GHeAka;
    authType = AuthType.FIVE_G_AKA;
  }

  const newSqnInt = (parseInt(sequenceNumber, 16) + 1) % 0x1000000000000;
  const newSqn = newSqnInt.toString(16).padStart(12, '0').toUpperCase();

  try {
    const subscribersCollection = getCollection<SubscriberData>('subscribers');
    if (subscriber.subscribedData?.authenticationSubscription) {
      await subscribersCollection.updateOne(
        { supi },
        { $set: { 'subscribedData.authenticationSubscription.sequenceNumber': newSqn } }
      );
    } else {
      await subscribersCollection.updateOne(
        { supi },
        { $set: { sequenceNumber: newSqn } }
      );
    }
  } catch (error) {
    auditLog('auth_vector_generation_failed', {
      supi: supi,
      reason: 'database_update_error',
      error: error instanceof Error ? error.message : String(error)
    }, 'Auth vector generation failed: Failed to update sequence number');
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Failed to update sequence number'
    });
  }

  const authResult: AuthenticationInfoResult = {
    authType: authType,
    authenticationVector: authVector,
    supi: supi
  };

  auditLog('auth_vector_generation_success', {
    supi: supi,
    auth_method: authMethod,
    serving_network: authRequest.servingNetworkName,
    ausf_instance: authRequest.ausfInstanceId
  }, 'Authentication vector generated successfully');

  return res.status(200).json(authResult);
});

router.get('/:supiOrSuci/security-information-rg', async (req: Request, res: Response) => {
  const { supiOrSuci } = req.params;
  const authenticatedInd = req.query['authenticated-ind'];
  const supportedFeatures = req.query['supported-features'] as string | undefined;
  const plmnIdParam = req.query['plmn-id'] as string | undefined;

  if (authenticatedInd === undefined || authenticatedInd === null) {
    return res.status(400).json(createMissingParameterError('authenticated-ind query parameter is required'));
  }

  const authIndInput = authenticatedInd === 'true';
  if (authenticatedInd !== 'true' && authenticatedInd !== 'false') {
    return res.status(400).json(createInvalidParameterError('authenticated-ind must be a boolean value'));
  }

  let plmnId: PlmnId | undefined;
  if (plmnIdParam) {
    try {
      plmnId = JSON.parse(plmnIdParam);
      if (!plmnId?.mcc || !plmnId?.mnc) {
        return res.status(400).json(createInvalidParameterError('plmn-id must contain mcc and mnc'));
      }
    } catch {
      return res.status(400).json(createInvalidParameterError('plmn-id must be a valid JSON object'));
    }
  }

  let supi = supiOrSuci;

  if (suciPattern.test(supiOrSuci)) {
    const result = deconcealSuci(supiOrSuci);
    if ('error' in result) {
      return res.status(501).json(createNotImplementedError(result.error));
    }
    supi = result.supi;
  }

  if (!supi.startsWith('imsi-')) {
    return res.status(400).json(createInvalidParameterError('Invalid SUPI format, must start with imsi-'));
  }

  let subscriber: SubscriberData | null;
  try {
    const subscribersCollection = getCollection<SubscriberData>('subscribers');
    subscriber = await subscribersCollection.findOne({ supi });
  } catch (error) {
    return res.status(500).json(createInternalError('Database operation failed'));
  }

  if (!subscriber) {
    return res.status(404).json({
      type: 'urn:3gpp:error:not-found',
      title: 'Not Found',
      status: 404,
      detail: 'Subscriber not found',
      cause: 'USER_NOT_FOUND'
    });
  }

  let permanentKey: string;
  let operatorKey: string;
  let sequenceNumber: string;

  if (subscriber.subscribedData?.authenticationSubscription) {
    const authSub = subscriber.subscribedData.authenticationSubscription;
    permanentKey = authSub.permanentKey?.permanentKeyValue || subscriber.permanentKey;
    operatorKey = authSub.milenage?.op?.opValue || subscriber.operatorKey;
    sequenceNumber = authSub.sequenceNumber || subscriber.sequenceNumber;
  } else {
    permanentKey = subscriber.permanentKey;
    operatorKey = subscriber.operatorKey;
    sequenceNumber = subscriber.sequenceNumber;
  }

  const hasCredentials = !!(permanentKey && operatorKey && sequenceNumber);

  if (!hasCredentials) {
    return res.status(403).json(createAuthenticationRejectedError('Subscriber does not have required authentication subscription data'));
  }

  const rgAuthCtx: RgAuthCtx = {
    authInd: true,
    supi: supi,
    ...(supportedFeatures && { supportedFeatures })
  };

  return res.status(200).json(rgAuthCtx);
});

router.post('/:supi/auth-events', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const authEvent: AuthEvent = req.body;

  if (!authEvent || typeof authEvent !== 'object') {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  if (!authEvent.nfInstanceId) {
    return res.status(400).json(createInvalidParameterError('nfInstanceId is required'));
  }

  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!uuidPattern.test(authEvent.nfInstanceId)) {
    return res.status(400).json(createInvalidParameterError('nfInstanceId must be a valid UUID'));
  }

  if (authEvent.success === undefined || authEvent.success === null) {
    return res.status(400).json(createInvalidParameterError('success is required'));
  }

  if (typeof authEvent.success !== 'boolean') {
    return res.status(400).json(createInvalidParameterError('success must be a boolean'));
  }

  if (!authEvent.timeStamp) {
    return res.status(400).json(createInvalidParameterError('timeStamp is required'));
  }

  if (isNaN(Date.parse(authEvent.timeStamp))) {
    return res.status(400).json(createInvalidParameterError('timeStamp must be a valid ISO 8601 DateTime'));
  }

  if (!authEvent.authType) {
    return res.status(400).json(createInvalidParameterError('authType is required'));
  }

  if (!Object.values(AuthType).includes(authEvent.authType)) {
    return res.status(400).json(createInvalidParameterError('authType must be a valid AuthType value'));
  }

  if (!authEvent.servingNetworkName) {
    return res.status(400).json(createInvalidParameterError('servingNetworkName is required'));
  }

  const snnPattern = /^(5G:mnc[0-9]{3}[.]mcc[0-9]{3}[.]3gppnetwork[.]org(:[A-F0-9]{11})?)$/;
  if (!snnPattern.test(authEvent.servingNetworkName)) {
    return res.status(400).json(createInvalidParameterError('servingNetworkName must match 3GPP serving network name format'));
  }

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid SUPI format'));
  }

  if (authEvent.resetIds !== undefined) {
    if (!Array.isArray(authEvent.resetIds) || authEvent.resetIds.length < 1) {
      return res.status(400).json(createInvalidParameterError('resetIds must be a non-empty array'));
    }
  }

  auditLog('auth_event_received', {
    supi: supi,
    success: authEvent.success,
    auth_type: authEvent.authType,
    serving_network: authEvent.servingNetworkName,
    nf_instance: authEvent.nfInstanceId,
    timestamp: authEvent.timeStamp
  }, `Authentication event received: ${authEvent.success ? 'SUCCESS' : 'FAILURE'}`);

  let subscriber: SubscriberData | null;
  try {
    const subscribersCollection = getCollection<SubscriberData>('subscribers');
    subscriber = await subscribersCollection.findOne({ supi });
  } catch (error) {
    return res.status(500).json(createInternalError('Database operation failed'));
  }

  if (!subscriber) {
    return res.status(404).json(createNotFoundError(`Subscriber with SUPI ${supi} not found`));
  }

  if (authEvent.authRemovalInd === true) {
    try {
      const authEventsCollection = getCollection<AuthEvent & { authEventId: string; supi: string }>('authEvents');
      await authEventsCollection.deleteMany({ supi });
    } catch (error) {
      return res.status(500).json(createInternalError('Failed to remove authentication status'));
    }

    return res.status(204).send();
  }

  const authEventId = randomUUID();

  const authEventRecord = {
    authEventId,
    supi,
    nfInstanceId: authEvent.nfInstanceId,
    success: authEvent.success,
    timeStamp: authEvent.timeStamp,
    authType: authEvent.authType,
    servingNetworkName: authEvent.servingNetworkName,
    authRemovalInd: false,
    nfSetId: authEvent.nfSetId,
    resetIds: authEvent.resetIds,
    dataRestorationCallbackUri: authEvent.dataRestorationCallbackUri,
    udrRestartInd: authEvent.udrRestartInd ?? false,
    lastSynchronizationTime: authEvent.lastSynchronizationTime,
    nswoInd: authEvent.nswoInd ?? false
  };

  try {
    const authEventsCollection = getCollection<AuthEvent & { authEventId: string; supi: string }>('authEvents');
    await authEventsCollection.insertOne(authEventRecord);
  } catch (error) {
    return res.status(500).json(createInternalError('Failed to store authentication event'));
  }

  const location = `${req.protocol}://${req.get('host')}/nudm-ueau/v1/${supi}/auth-events/${authEventId}`;
  res.setHeader('Location', location);

  return res.status(201).json({
    nfInstanceId: authEvent.nfInstanceId,
    success: authEvent.success,
    timeStamp: authEvent.timeStamp,
    authType: authEvent.authType,
    servingNetworkName: authEvent.servingNetworkName,
    ...(authEvent.authRemovalInd !== undefined && { authRemovalInd: authEvent.authRemovalInd }),
    ...(authEvent.nfSetId && { nfSetId: authEvent.nfSetId }),
    ...(authEvent.resetIds && { resetIds: authEvent.resetIds }),
    ...(authEvent.dataRestorationCallbackUri && { dataRestorationCallbackUri: authEvent.dataRestorationCallbackUri }),
    ...(authEvent.udrRestartInd !== undefined && { udrRestartInd: authEvent.udrRestartInd }),
    ...(authEvent.lastSynchronizationTime && { lastSynchronizationTime: authEvent.lastSynchronizationTime }),
    ...(authEvent.nswoInd !== undefined && { nswoInd: authEvent.nswoInd })
  });
});

router.post('/:supi/hss-security-information/:hssAuthType/generate-av', async (req: Request, res: Response) => {
  const { supi, hssAuthType } = req.params;
  const hssAuthRequest: HssAuthenticationInfoRequest = req.body;

  // Validate request body
  if (!hssAuthRequest || typeof hssAuthRequest !== 'object' || Array.isArray(hssAuthRequest)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  // Validate required fields
  if (hssAuthRequest.numOfRequestedVectors === undefined || hssAuthRequest.numOfRequestedVectors === null) {
    return res.status(400).json(createInvalidParameterError('numOfRequestedVectors is required'));
  }

  if (!Number.isInteger(hssAuthRequest.numOfRequestedVectors) || hssAuthRequest.numOfRequestedVectors < 1 || hssAuthRequest.numOfRequestedVectors > 32) {
    return res.status(400).json(createInvalidParameterError('numOfRequestedVectors must be an integer between 1 and 32'));
  }

  // Validate SUPI format
  if (!supi.startsWith('imsi-')) {
    return res.status(400).json(createInvalidParameterError('Invalid SUPI format, must start with imsi-'));
  }

  // Map URI format to enum format
  const hssAuthTypeMap: { [key: string]: HssAuthType } = {
    'eps-aka': HssAuthType.EPS_AKA,
    'eap-aka': HssAuthType.EAP_AKA,
    'eap-aka-prime': HssAuthType.EAP_AKA_PRIME,
    'ims-aka': HssAuthType.IMS_AKA,
    'gba-aka': HssAuthType.GBA_AKA,
    'umts-aka': HssAuthType.UMTS_AKA
  };

  const mappedHssAuthType = hssAuthTypeMap[hssAuthType.toLowerCase()];
  if (!mappedHssAuthType) {
    return res.status(400).json(createInvalidParameterError(`Invalid hssAuthType: ${hssAuthType}. Must be one of: eps-aka, eap-aka, eap-aka-prime, ims-aka, gba-aka, umts-aka`));
  }

  // Verify the hssAuthType in request body matches the URI parameter
  if (hssAuthRequest.hssAuthType && hssAuthRequest.hssAuthType !== mappedHssAuthType) {
    return res.status(400).json(createInvalidParameterError('hssAuthType in request body does not match URI parameter'));
  }

  let subscriber: SubscriberData | null;
  try {
    const subscribersCollection = getCollection<SubscriberData>('subscribers');
    subscriber = await subscribersCollection.findOne({ supi });
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Database operation failed'
    });
  }

  if (!subscriber) {
    return res.status(404).json(createNotFoundError(`Subscriber with SUPI ${supi} not found`));
  }
  let permanentKey: string;
  let operatorKey: string;
  let sequenceNumber: string;
  let amf = '8000';

  if (subscriber.subscribedData?.authenticationSubscription) {
    const authSub = subscriber.subscribedData.authenticationSubscription;
    permanentKey = authSub.permanentKey?.permanentKeyValue || subscriber.permanentKey;
    operatorKey = authSub.milenage?.op?.opValue || subscriber.operatorKey;
    sequenceNumber = authSub.sequenceNumber || subscriber.sequenceNumber;
    amf = authSub.authenticationManagementField || '8000';
  } else {
    permanentKey = subscriber.permanentKey;
    operatorKey = subscriber.operatorKey;
    sequenceNumber = subscriber.sequenceNumber;
  }

  if (!permanentKey || !operatorKey || !sequenceNumber) {
    auditLog('hss_av_generation_failed', {
      supi: supi,
      reason: 'missing_credentials'
    }, 'HSS AV generation failed: Missing authentication credentials');
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Missing authentication credentials for subscriber'
    });
  }

  const credHexPattern = /^[0-9A-Fa-f]+$/;
  if (!credHexPattern.test(permanentKey) || permanentKey.length !== 32) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Invalid permanentKey format in subscriber data'
    });
  }
  if (!credHexPattern.test(operatorKey) || operatorKey.length !== 32) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Invalid operatorKey format in subscriber data'
    });
  }
  if (!credHexPattern.test(sequenceNumber) || sequenceNumber.length !== 12) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Invalid sequenceNumber format in subscriber data'
    });
  }

  auditLog('key_access', {
    supi: supi,
    key_types: ['permanentKey', 'operatorKey'],
    purpose: 'hss_av_generation'
  }, 'Accessed subscriber cryptographic keys for HSS authentication');

  if (hssAuthRequest.resynchronizationInfo) {
    const hexPattern = /^[0-9A-Fa-f]+$/;
    const resyncRand = hssAuthRequest.resynchronizationInfo.rand;
    const resyncAuts = hssAuthRequest.resynchronizationInfo.auts;

    if (!resyncRand || !hexPattern.test(resyncRand) || resyncRand.length !== 32) {
      return res.status(400).json(createInvalidParameterError('resynchronizationInfo.rand must be exactly 32 hex characters'));
    }
    if (!resyncAuts || !hexPattern.test(resyncAuts) || resyncAuts.length !== 28) {
      return res.status(400).json(createInvalidParameterError('resynchronizationInfo.auts must be exactly 28 hex characters'));
    }

    auditLog('hss_resynchronization_request', {
      supi: supi,
      rand: resyncRand
    }, 'HSS sequence number resynchronization requested');

    const kBuf = Buffer.from(permanentKey, 'hex');
    const opBuf = Buffer.from(operatorKey, 'hex');
    const randBuf = Buffer.from(resyncRand, 'hex');
    const autsBuf = Buffer.from(resyncAuts, 'hex');
    const amfBuf = Buffer.from(amf, 'hex');

    const sqnMs = processAuts(kBuf, opBuf, randBuf, autsBuf, amfBuf);

    if (!sqnMs) {
      auditLog('hss_resynchronization_failed', {
        supi: supi,
        reason: 'auts_validation_failed'
      }, 'HSS resynchronization failed: AUTS validation failed');
      return res.status(403).json({
        type: 'urn:3gpp:error:authentication-rejected',
        title: 'Authentication Rejected',
        status: 403,
        detail: 'AUTS validation failed'
      });
    }

    const sqnMsInt = parseInt(sqnMs, 16);
    const newSqnInt = (sqnMsInt + 32) & 0xFFFFFFFFFFFF;
    sequenceNumber = newSqnInt.toString(16).padStart(12, '0').toUpperCase();

    try {
      const subscribersCollection = getCollection<SubscriberData>('subscribers');
      let updateResult;
      if (subscriber.subscribedData?.authenticationSubscription) {
        updateResult = await subscribersCollection.updateOne(
          { supi },
          { $set: { 'subscribedData.authenticationSubscription.sequenceNumber': sequenceNumber } }
        );
      } else {
        updateResult = await subscribersCollection.updateOne(
          { supi },
          { $set: { sequenceNumber: sequenceNumber } }
        );
      }

      if (updateResult.matchedCount === 0) {
        auditLog('hss_resynchronization_failed', {
          supi: supi,
          reason: 'database_update_failed'
        }, 'HSS resynchronization failed: Failed to persist new SQN');
        return res.status(500).json({
          type: 'urn:3gpp:error:internal-error',
          title: 'Internal Server Error',
          status: 500,
          detail: 'Failed to persist resynchronized sequence number'
        });
      }
    } catch (error) {
      auditLog('hss_resynchronization_failed', {
        supi: supi,
        reason: 'database_error',
        error: error instanceof Error ? error.message : String(error)
      }, 'HSS resynchronization failed: Database error');
      return res.status(500).json({
        type: 'urn:3gpp:error:internal-error',
        title: 'Internal Server Error',
        status: 500,
        detail: 'Failed to persist resynchronized sequence number'
      });
    }

    auditLog('hss_resynchronization_success', {
      supi: supi,
      new_sequence_number: sequenceNumber
    }, 'HSS sequence number resynchronization completed successfully');
  }

  const authVectors: (AvEpsAka | AvImsGbaEapAka | AvEapAkaPrime)[] = [];
  let currentSqn = sequenceNumber;

  for (let i = 0; i < hssAuthRequest.numOfRequestedVectors; i++) {
    const rand = generateRand();
    const randBuf = Buffer.from(rand, 'hex');
    const kBuf = Buffer.from(permanentKey, 'hex');
    const opBuf = Buffer.from(operatorKey, 'hex');
    const sqnBuf = Buffer.from(currentSqn, 'hex');
    const amfBuf = Buffer.from(amf, 'hex');

    const milenageOutput = milenage(kBuf, opBuf, randBuf, sqnBuf, amfBuf);

    const sqnXorAk = Buffer.alloc(6);
    for (let j = 0; j < 6; j++) {
      sqnXorAk[j] = sqnBuf[j] ^ milenageOutput.ak[j];
    }

    const autn = Buffer.concat([sqnXorAk, amfBuf, milenageOutput.mac_a]).toString('hex').toUpperCase();
    const xres = milenageOutput.res.toString('hex').toUpperCase();

    switch (mappedHssAuthType) {
      case HssAuthType.EPS_AKA: {
        // Extract PLMN ID from servingNetworkId if provided, otherwise use default
        let plmnIdBuf: Buffer;
        if (hssAuthRequest.servingNetworkId) {
          const mcc = hssAuthRequest.servingNetworkId.mcc;
          const mnc = hssAuthRequest.servingNetworkId.mnc;
          // Encode PLMN ID (3 bytes)
          const mccDigits = mcc.split('');
          const mncDigits = mnc.split('');
          plmnIdBuf = Buffer.from([
            parseInt(mccDigits[1] + mccDigits[0], 16),
            parseInt((mncDigits.length === 2 ? 'f' : mncDigits[2]) + mccDigits[2], 16),
            parseInt(mncDigits[1] + mncDigits[0], 16)
          ]);
        } else {
          // Default PLMN ID (001-01)
          plmnIdBuf = Buffer.from([0x00, 0xf1, 0x10]);
        }

        const kasme = computeKasme(milenageOutput.ck, milenageOutput.ik, plmnIdBuf, sqnXorAk);

        const epsAkaVector: AvEpsAka = {
          avType: HssAvType.EPS_AKA,
          rand: rand,
          xres: xres,
          autn: autn,
          kasme: kasme
        };
        authVectors.push(epsAkaVector);
        break;
      }

      case HssAuthType.IMS_AKA:
      case HssAuthType.GBA_AKA:
      case HssAuthType.EAP_AKA: {
        const imsGbaEapVector: AvImsGbaEapAka = {
          avType: mappedHssAuthType === HssAuthType.IMS_AKA ? HssAvType.IMS_AKA :
                  mappedHssAuthType === HssAuthType.GBA_AKA ? HssAvType.GBA_AKA :
                  HssAvType.EAP_AKA,
          rand: rand,
          xres: xres,
          autn: autn,
          ck: milenageOutput.ck.toString('hex').toUpperCase(),
          ik: milenageOutput.ik.toString('hex').toUpperCase()
        };
        authVectors.push(imsGbaEapVector);
        break;
      }

      case HssAuthType.EAP_AKA_PRIME: {
        // For EAP-AKA', we need a serving network name
        // Use servingNetworkId to construct it, or default
        let servingNetworkName = '5G:mnc001.mcc001.3gppnetwork.org';
        if (hssAuthRequest.servingNetworkId) {
          const mcc = hssAuthRequest.servingNetworkId.mcc;
          const mnc = hssAuthRequest.servingNetworkId.mnc;
          servingNetworkName = `5G:mnc${mnc.padStart(3, '0')}.mcc${mcc}.3gppnetwork.org`;
        }

        const { ckPrime, ikPrime } = computeCkPrimeIkPrime(
          milenageOutput.ck,
          milenageOutput.ik,
          servingNetworkName,
          sqnXorAk
        );

        const eapAkaPrimeVector: AvEapAkaPrime = {
          avType: AvType.EAP_AKA_PRIME,
          rand: rand,
          xres: xres,
          autn: autn,
          ckPrime: ckPrime,
          ikPrime: ikPrime
        };
        authVectors.push(eapAkaPrimeVector);
        break;
      }

      case HssAuthType.UMTS_AKA: {
        // UMTS-AKA is similar to IMS/GBA/EAP-AKA
        const umtsVector: AvImsGbaEapAka = {
          avType: HssAvType.UMTS_AKA,
          rand: rand,
          xres: xres,
          autn: autn,
          ck: milenageOutput.ck.toString('hex').toUpperCase(),
          ik: milenageOutput.ik.toString('hex').toUpperCase()
        };
        authVectors.push(umtsVector);
        break;
      }

      default:
        return res.status(501).json({
          type: 'urn:3gpp:error:not-implemented',
          title: 'Not Implemented',
          status: 501,
          detail: `Authentication type ${mappedHssAuthType} is not yet implemented`
        });
    }

    // Increment sequence number for next vector
    const sqnInt = parseInt(currentSqn, 16) + 1;
    currentSqn = sqnInt.toString(16).padStart(12, '0').toUpperCase();
  }

  try {
    const subscribersCollection = getCollection<SubscriberData>('subscribers');
    if (subscriber.subscribedData?.authenticationSubscription) {
      await subscribersCollection.updateOne(
        { supi },
        { $set: { 'subscribedData.authenticationSubscription.sequenceNumber': currentSqn } }
      );
    } else {
      await subscribersCollection.updateOne(
        { supi },
        { $set: { sequenceNumber: currentSqn } }
      );
    }
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Failed to update sequence number'
    });
  }

  const result: HssAuthenticationInfoResult = {
    hssAuthenticationVectors: authVectors as any,
    supportedFeatures: hssAuthRequest.supportedFeatures
  };

  return res.status(200).json(result);
});

router.put('/:supi/auth-events/:authEventId', async (req: Request, res: Response) => {
  const { supi, authEventId } = req.params;
  const authEvent: AuthEvent = req.body;

  if (!authEvent || typeof authEvent !== 'object') {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  if (!authEvent.nfInstanceId) {
    return res.status(400).json(createInvalidParameterError('nfInstanceId is required'));
  }

  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!uuidPattern.test(authEvent.nfInstanceId)) {
    return res.status(400).json(createInvalidParameterError('nfInstanceId must be a valid UUID'));
  }

  if (authEvent.success === undefined || authEvent.success === null) {
    return res.status(400).json(createInvalidParameterError('success is required'));
  }

  if (typeof authEvent.success !== 'boolean') {
    return res.status(400).json(createInvalidParameterError('success must be a boolean'));
  }

  if (!authEvent.timeStamp) {
    return res.status(400).json(createInvalidParameterError('timeStamp is required'));
  }

  if (isNaN(Date.parse(authEvent.timeStamp))) {
    return res.status(400).json(createInvalidParameterError('timeStamp must be a valid ISO 8601 DateTime'));
  }

  if (!authEvent.authType) {
    return res.status(400).json(createInvalidParameterError('authType is required'));
  }

  if (!Object.values(AuthType).includes(authEvent.authType)) {
    return res.status(400).json(createInvalidParameterError('authType must be a valid AuthType value'));
  }

  if (!authEvent.servingNetworkName) {
    return res.status(400).json(createInvalidParameterError('servingNetworkName is required'));
  }

  const snnPattern = /^(5G:mnc[0-9]{3}[.]mcc[0-9]{3}[.]3gppnetwork[.]org(:[A-F0-9]{11})?)$/;
  if (!snnPattern.test(authEvent.servingNetworkName)) {
    return res.status(400).json(createInvalidParameterError('servingNetworkName must match 3GPP serving network name format'));
  }

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid SUPI format'));
  }

  if (authEvent.resetIds !== undefined) {
    if (!Array.isArray(authEvent.resetIds) || authEvent.resetIds.length < 1) {
      return res.status(400).json(createInvalidParameterError('resetIds must be a non-empty array'));
    }
  }

  let subscriber: SubscriberData | null;
  try {
    const subscribersCollection = getCollection<SubscriberData>('subscribers');
    subscriber = await subscribersCollection.findOne({ supi });
  } catch (error) {
    return res.status(500).json(createInternalError('Database operation failed'));
  }

  if (!subscriber) {
    return res.status(404).json(createNotFoundError(`Subscriber with SUPI ${supi} not found`));
  }

  if (authEvent.authRemovalInd === true) {
    try {
      const authEventsCollection = getCollection<AuthEvent & { authEventId: string; supi: string }>('authEvents');
      await authEventsCollection.deleteMany({ supi });
    } catch (error) {
      return res.status(500).json(createInternalError('Failed to remove authentication status'));
    }

    auditLog('auth_event_removal', {
      supi,
      auth_event_id: authEventId,
      nf_instance: authEvent.nfInstanceId
    }, 'Authentication status removed via PUT');

    return res.status(204).send();
  }

  let existingAuthEvent;
  try {
    const authEventsCollection = getCollection<AuthEvent & { authEventId: string; supi: string }>('authEvents');
    existingAuthEvent = await authEventsCollection.findOne({ authEventId, supi });
  } catch (error) {
    return res.status(500).json(createInternalError('Database operation failed'));
  }

  if (!existingAuthEvent) {
    return res.status(404).json(createNotFoundError(`Auth event with ID ${authEventId} not found for SUPI ${supi}`));
  }

  try {
    const authEventsCollection = getCollection<AuthEvent & { authEventId: string; supi: string }>('authEvents');

    const setFields: Record<string, any> = {
      nfInstanceId: authEvent.nfInstanceId,
      success: authEvent.success,
      timeStamp: authEvent.timeStamp,
      authType: authEvent.authType,
      servingNetworkName: authEvent.servingNetworkName,
      authRemovalInd: false,
      udrRestartInd: authEvent.udrRestartInd ?? false,
      nswoInd: authEvent.nswoInd ?? false
    };

    if (authEvent.nfSetId !== undefined) setFields.nfSetId = authEvent.nfSetId;
    if (authEvent.resetIds !== undefined) setFields.resetIds = authEvent.resetIds;
    if (authEvent.dataRestorationCallbackUri !== undefined) setFields.dataRestorationCallbackUri = authEvent.dataRestorationCallbackUri;
    if (authEvent.lastSynchronizationTime !== undefined) setFields.lastSynchronizationTime = authEvent.lastSynchronizationTime;

    const unsetFields: Record<string, any> = {};
    if (authEvent.nfSetId === undefined) unsetFields.nfSetId = '';
    if (authEvent.resetIds === undefined) unsetFields.resetIds = '';
    if (authEvent.dataRestorationCallbackUri === undefined) unsetFields.dataRestorationCallbackUri = '';
    if (authEvent.lastSynchronizationTime === undefined) unsetFields.lastSynchronizationTime = '';

    const updateOp: Record<string, any> = { $set: setFields };
    if (Object.keys(unsetFields).length > 0) updateOp.$unset = unsetFields;

    await authEventsCollection.updateOne({ authEventId, supi }, updateOp);
  } catch (error) {
    return res.status(500).json(createInternalError('Failed to update auth event'));
  }

  auditLog('auth_event_updated', {
    supi,
    auth_event_id: authEventId,
    success: authEvent.success,
    auth_type: authEvent.authType,
    serving_network: authEvent.servingNetworkName,
    nf_instance: authEvent.nfInstanceId,
    timestamp: authEvent.timeStamp
  }, `Authentication event updated: ${authEvent.success ? 'SUCCESS' : 'FAILURE'}`);

  return res.status(204).send();
});

router.delete('/:supi/auth-events/:authEventId', async (req: Request, res: Response) => {
  const { supi, authEventId } = req.params;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid SUPI format'));
  }

  let subscriber: SubscriberData | null;
  try {
    const subscribersCollection = getCollection<SubscriberData>('subscribers');
    subscriber = await subscribersCollection.findOne({ supi });
  } catch (error) {
    return res.status(500).json(createInternalError('Database operation failed'));
  }

  if (!subscriber) {
    return res.status(404).json(createNotFoundError(`Subscriber with SUPI ${supi} not found`));
  }

  try {
    const authEventsCollection = getCollection<AuthEvent & { authEventId: string; supi: string }>('authEvents');
    const deleteResult = await authEventsCollection.deleteOne({ authEventId, supi });

    if (deleteResult.deletedCount === 0) {
      return res.status(404).json(createNotFoundError(`Auth event with ID ${authEventId} not found for SUPI ${supi}`));
    }
  } catch (error) {
    return res.status(500).json(createInternalError('Failed to delete auth event'));
  }

  auditLog('auth_event_deleted', {
    supi,
    auth_event_id: authEventId
  }, 'Authentication event deleted');

  return res.status(204).send();
});

router.post('/:supi/gba-security-information/generate-av', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const gbaAuthRequest: GbaAuthenticationInfoRequest = req.body;

  // Validate request body
  if (!gbaAuthRequest || typeof gbaAuthRequest !== 'object' || Array.isArray(gbaAuthRequest)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  // Validate required fields
  if (!gbaAuthRequest.authType) {
    return res.status(400).json(createInvalidParameterError('authType is required'));
  }

  // Validate authType value
  if (gbaAuthRequest.authType !== GbaAuthType.DIGEST_AKAV1_MD5) {
    return res.status(400).json(createInvalidParameterError(`Invalid authType: ${gbaAuthRequest.authType}. Must be DIGEST_AKAV1_MD5`));
  }

  // Validate SUPI format
  if (!supi.startsWith('imsi-')) {
    return res.status(400).json(createInvalidParameterError('Invalid SUPI format, must start with imsi-'));
  }

  let subscriber: SubscriberData | null;
  try {
    const subscribersCollection = getCollection<SubscriberData>('subscribers');
    subscriber = await subscribersCollection.findOne({ supi });
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Database operation failed'
    });
  }

  if (!subscriber) {
    return res.status(404).json(createNotFoundError(`Subscriber with SUPI ${supi} not found`));
  }
  let permanentKey: string;
  let operatorKey: string;
  let sequenceNumber: string;
  let amf = '8000';

  if (subscriber.subscribedData?.authenticationSubscription) {
    const authSub = subscriber.subscribedData.authenticationSubscription;
    permanentKey = authSub.permanentKey?.permanentKeyValue || subscriber.permanentKey;
    operatorKey = authSub.milenage?.op?.opValue || subscriber.operatorKey;
    sequenceNumber = authSub.sequenceNumber || subscriber.sequenceNumber;
    amf = authSub.authenticationManagementField || '8000';
  } else {
    permanentKey = subscriber.permanentKey;
    operatorKey = subscriber.operatorKey;
    sequenceNumber = subscriber.sequenceNumber;
  }

  if (!permanentKey || !operatorKey || !sequenceNumber) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Missing authentication credentials for subscriber'
    });
  }

  const credHexPattern = /^[0-9A-Fa-f]+$/;
  if (!credHexPattern.test(permanentKey) || permanentKey.length !== 32) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Invalid permanentKey format in subscriber data'
    });
  }
  if (!credHexPattern.test(operatorKey) || operatorKey.length !== 32) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Invalid operatorKey format in subscriber data'
    });
  }
  if (!credHexPattern.test(sequenceNumber) || sequenceNumber.length !== 12) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Invalid sequenceNumber format in subscriber data'
    });
  }

  auditLog('key_access', {
    supi: supi,
    key_types: ['permanentKey', 'operatorKey'],
    purpose: 'gba_av_generation'
  }, 'Accessed subscriber cryptographic keys for GBA authentication');

  if (gbaAuthRequest.resynchronizationInfo) {
    const hexPattern = /^[0-9A-Fa-f]+$/;
    const resyncRand = gbaAuthRequest.resynchronizationInfo.rand;
    const resyncAuts = gbaAuthRequest.resynchronizationInfo.auts;

    if (!resyncRand || !hexPattern.test(resyncRand) || resyncRand.length !== 32) {
      return res.status(400).json(createInvalidParameterError('resynchronizationInfo.rand must be exactly 32 hex characters'));
    }
    if (!resyncAuts || !hexPattern.test(resyncAuts) || resyncAuts.length !== 28) {
      return res.status(400).json(createInvalidParameterError('resynchronizationInfo.auts must be exactly 28 hex characters'));
    }

    auditLog('gba_resynchronization_request', {
      supi: supi,
      rand: resyncRand
    }, 'GBA sequence number resynchronization requested');

    const kBuf = Buffer.from(permanentKey, 'hex');
    const opBuf = Buffer.from(operatorKey, 'hex');
    const randBuf = Buffer.from(resyncRand, 'hex');
    const autsBuf = Buffer.from(resyncAuts, 'hex');
    const amfBuf = Buffer.from(amf, 'hex');

    const sqnMs = processAuts(kBuf, opBuf, randBuf, autsBuf, amfBuf);

    if (!sqnMs) {
      auditLog('gba_resynchronization_failed', {
        supi: supi,
        reason: 'auts_validation_failed'
      }, 'GBA resynchronization failed: AUTS validation failed');
      return res.status(403).json({
        type: 'urn:3gpp:error:authentication-rejected',
        title: 'Authentication Rejected',
        status: 403,
        detail: 'AUTS validation failed'
      });
    }

    const sqnMsInt = parseInt(sqnMs, 16);
    const newSqnInt = (sqnMsInt + 32) & 0xFFFFFFFFFFFF;
    sequenceNumber = newSqnInt.toString(16).padStart(12, '0').toUpperCase();

    try {
      const subscribersCollection = getCollection<SubscriberData>('subscribers');
      if (subscriber.subscribedData?.authenticationSubscription) {
        await subscribersCollection.updateOne(
          { supi },
          { $set: { 'subscribedData.authenticationSubscription.sequenceNumber': sequenceNumber } }
        );
      } else {
        await subscribersCollection.updateOne(
          { supi },
          { $set: { sequenceNumber: sequenceNumber } }
        );
      }
    } catch (error) {
      auditLog('gba_resynchronization_failed', {
        supi: supi,
        reason: 'database_error',
        error: error instanceof Error ? error.message : String(error)
      }, 'GBA resynchronization failed: Database error');
      return res.status(500).json({
        type: 'urn:3gpp:error:internal-error',
        title: 'Internal Server Error',
        status: 500,
        detail: 'Failed to persist resynchronized sequence number'
      });
    }
  }

  const rand = generateRand();
  const randBuf = Buffer.from(rand, 'hex');
  const kBuf = Buffer.from(permanentKey, 'hex');
  const opBuf = Buffer.from(operatorKey, 'hex');
  const sqnBuf = Buffer.from(sequenceNumber, 'hex');
  const amfBuf = Buffer.from(amf, 'hex');

  let milenageOutput: MilenageOutput;
  try {
    milenageOutput = milenage(kBuf, opBuf, randBuf, sqnBuf, amfBuf);
  } catch (error) {
    auditLog('gba_av_generation_failed', {
      supi: supi,
      reason: 'milenage_error',
      error: error instanceof Error ? error.message : String(error)
    }, 'GBA AV generation failed: Milenage computation error');
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Authentication vector generation failed'
    });
  }

  const sqnXorAk = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) {
    sqnXorAk[i] = sqnBuf[i] ^ milenageOutput.ak[i];
  }

  const autn = Buffer.concat([sqnXorAk, amfBuf, milenageOutput.mac_a]).toString('hex').toUpperCase();
  const xres = milenageOutput.res.toString('hex').toUpperCase();

  const threeGAkaAv: ThreeGAkaAv = {
    rand: rand,
    xres: xres,
    autn: autn,
    ck: milenageOutput.ck.toString('hex').toUpperCase(),
    ik: milenageOutput.ik.toString('hex').toUpperCase()
  };

  const newSqnInt = (parseInt(sequenceNumber, 16) + 1) % 0x1000000000000;
  const newSqn = newSqnInt.toString(16).padStart(12, '0').toUpperCase();

  try {
    const subscribersCollection = getCollection<SubscriberData>('subscribers');
    if (subscriber.subscribedData?.authenticationSubscription) {
      await subscribersCollection.updateOne(
        { supi },
        { $set: { 'subscribedData.authenticationSubscription.sequenceNumber': newSqn } }
      );
    } else {
      await subscribersCollection.updateOne(
        { supi },
        { $set: { sequenceNumber: newSqn } }
      );
    }
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Failed to update sequence number'
    });
  }

  const result: GbaAuthenticationInfoResult = {
    '3gAkaAv': threeGAkaAv,
    supportedFeatures: gbaAuthRequest.supportedFeatures
  };

  return res.status(200).json(result);
});

router.post('/:supiOrSuci/prose-security-information/generate-av', async (req: Request, res: Response) => {
  const { supiOrSuci } = req.params;
  const proseAuthRequest: ProSeAuthenticationInfoRequest = req.body;

  if (!proseAuthRequest || typeof proseAuthRequest !== 'object' || Array.isArray(proseAuthRequest)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  if (!proseAuthRequest.servingNetworkName) {
    return res.status(400).json(createInvalidParameterError('servingNetworkName is required'));
  }

  if (!proseAuthRequest.relayServiceCode) {
    return res.status(400).json(createInvalidParameterError('relayServiceCode is required'));
  }

  let supi = supiOrSuci;

  if (suciPattern.test(supiOrSuci)) {
    const result = deconcealSuci(supiOrSuci);
    if ('error' in result) {
      return res.status(501).json(createNotImplementedError(result.error));
    }
    supi = result.supi;
  }

  if (!supi.startsWith('imsi-')) {
    return res.status(400).json(createInvalidParameterError('Invalid SUPI format, must start with imsi-'));
  }

  let subscriber: SubscriberData | null;
  try {
    const subscribersCollection = getCollection<SubscriberData>('subscribers');
    subscriber = await subscribersCollection.findOne({ supi });
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Database operation failed'
    });
  }

  if (!subscriber) {
    return res.status(404).json(createNotFoundError(`Subscriber with SUPI ${supi} not found`));
  }
  let permanentKey: string;
  let operatorKey: string;
  let sequenceNumber: string;
  let amf = '8000';

  if (subscriber.subscribedData?.authenticationSubscription) {
    const authSub = subscriber.subscribedData.authenticationSubscription;
    permanentKey = authSub.permanentKey?.permanentKeyValue || subscriber.permanentKey;
    operatorKey = authSub.milenage?.op?.opValue || subscriber.operatorKey;
    sequenceNumber = authSub.sequenceNumber || subscriber.sequenceNumber;
    amf = authSub.authenticationManagementField || '8000';
  } else {
    permanentKey = subscriber.permanentKey;
    operatorKey = subscriber.operatorKey;
    sequenceNumber = subscriber.sequenceNumber;
  }

  if (!permanentKey || !operatorKey || !sequenceNumber) {
    auditLog('prose_av_generation_failed', {
      supi: supi,
      reason: 'missing_credentials'
    }, 'ProSe AV generation failed: Missing authentication credentials');
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Missing authentication credentials for subscriber'
    });
  }

  const credHexPattern = /^[0-9A-Fa-f]+$/;
  if (!credHexPattern.test(permanentKey) || permanentKey.length !== 32) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Invalid permanentKey format in subscriber data'
    });
  }
  if (!credHexPattern.test(operatorKey) || operatorKey.length !== 32) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Invalid operatorKey format in subscriber data'
    });
  }
  if (!credHexPattern.test(sequenceNumber) || sequenceNumber.length !== 12) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Invalid sequenceNumber format in subscriber data'
    });
  }

  auditLog('key_access', {
    supi: supi,
    key_types: ['permanentKey', 'operatorKey'],
    purpose: 'prose_av_generation'
  }, 'Accessed subscriber cryptographic keys for ProSe authentication');

  if (proseAuthRequest.resynchronizationInfo) {
    const hexPattern = /^[0-9A-Fa-f]+$/;
    const resyncRand = proseAuthRequest.resynchronizationInfo.rand;
    const resyncAuts = proseAuthRequest.resynchronizationInfo.auts;

    if (!resyncRand || !hexPattern.test(resyncRand) || resyncRand.length !== 32) {
      return res.status(400).json(createInvalidParameterError('resynchronizationInfo.rand must be exactly 32 hex characters'));
    }
    if (!resyncAuts || !hexPattern.test(resyncAuts) || resyncAuts.length !== 28) {
      return res.status(400).json(createInvalidParameterError('resynchronizationInfo.auts must be exactly 28 hex characters'));
    }

    auditLog('prose_resynchronization_request', {
      supi: supi,
      rand: resyncRand
    }, 'ProSe sequence number resynchronization requested');

    const kBuf = Buffer.from(permanentKey, 'hex');
    const opBuf = Buffer.from(operatorKey, 'hex');
    const randBuf = Buffer.from(resyncRand, 'hex');
    const autsBuf = Buffer.from(resyncAuts, 'hex');
    const amfBuf = Buffer.from(amf, 'hex');

    const sqnMs = processAuts(kBuf, opBuf, randBuf, autsBuf, amfBuf);

    if (!sqnMs) {
      auditLog('prose_resynchronization_failed', {
        supi: supi,
        reason: 'auts_validation_failed'
      }, 'ProSe resynchronization failed: AUTS validation failed');
      return res.status(403).json({
        type: 'urn:3gpp:error:authentication-rejected',
        title: 'Authentication Rejected',
        status: 403,
        detail: 'AUTS validation failed'
      });
    }

    const sqnMsInt = parseInt(sqnMs, 16);
    const newSqnInt = (sqnMsInt + 32) & 0xFFFFFFFFFFFF;
    sequenceNumber = newSqnInt.toString(16).padStart(12, '0').toUpperCase();

    try {
      const subscribersCollection = getCollection<SubscriberData>('subscribers');
      let updateResult;
      if (subscriber.subscribedData?.authenticationSubscription) {
        updateResult = await subscribersCollection.updateOne(
          { supi },
          { $set: { 'subscribedData.authenticationSubscription.sequenceNumber': sequenceNumber } }
        );
      } else {
        updateResult = await subscribersCollection.updateOne(
          { supi },
          { $set: { sequenceNumber: sequenceNumber } }
        );
      }

      if (updateResult.matchedCount === 0) {
        auditLog('prose_resynchronization_failed', {
          supi: supi,
          reason: 'database_update_failed'
        }, 'ProSe resynchronization failed: Failed to persist new SQN');
        return res.status(500).json({
          type: 'urn:3gpp:error:internal-error',
          title: 'Internal Server Error',
          status: 500,
          detail: 'Failed to persist resynchronized sequence number'
        });
      }
    } catch (error) {
      auditLog('prose_resynchronization_failed', {
        supi: supi,
        reason: 'database_error',
        error: error instanceof Error ? error.message : String(error)
      }, 'ProSe resynchronization failed: Database error');
      return res.status(500).json({
        type: 'urn:3gpp:error:internal-error',
        title: 'Internal Server Error',
        status: 500,
        detail: 'Failed to persist resynchronized sequence number'
      });
    }

    auditLog('prose_resynchronization_success', {
      supi: supi,
      new_sequence_number: sequenceNumber
    }, 'ProSe sequence number resynchronization completed successfully');
  }

  const rand = generateRand();
  const randBuf = Buffer.from(rand, 'hex');
  const kBuf = Buffer.from(permanentKey, 'hex');
  const opBuf = Buffer.from(operatorKey, 'hex');
  const sqnBuf = Buffer.from(sequenceNumber, 'hex');
  const amfBuf = Buffer.from(amf, 'hex');

  const milenageOutput = milenage(kBuf, opBuf, randBuf, sqnBuf, amfBuf);

  const sqnXorAk = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) {
    sqnXorAk[i] = sqnBuf[i] ^ milenageOutput.ak[i];
  }

  const autn = Buffer.concat([sqnXorAk, amfBuf, milenageOutput.mac_a]).toString('hex').toUpperCase();
  const xres = milenageOutput.res.toString('hex').toUpperCase();

  const { ckPrime, ikPrime } = computeCkPrimeIkPrime(
    milenageOutput.ck,
    milenageOutput.ik,
    proseAuthRequest.servingNetworkName,
    sqnXorAk
  );

  const proseVector: AvEapAkaPrime = {
    avType: AvType.EAP_AKA_PRIME,
    rand: rand,
    xres: xres,
    autn: autn,
    ckPrime: ckPrime,
    ikPrime: ikPrime
  };

  const newSqnInt = (parseInt(sequenceNumber, 16) + 1) % 0x1000000000000;
  const newSqn = newSqnInt.toString(16).padStart(12, '0').toUpperCase();

  try {
    const subscribersCollection = getCollection<SubscriberData>('subscribers');
    if (subscriber.subscribedData?.authenticationSubscription) {
      await subscribersCollection.updateOne(
        { supi },
        { $set: { 'subscribedData.authenticationSubscription.sequenceNumber': newSqn } }
      );
    } else {
      await subscribersCollection.updateOne(
        { supi },
        { $set: { sequenceNumber: newSqn } }
      );
    }
  } catch (error) {
    auditLog('prose_av_generation_failed', {
      supi: supi,
      reason: 'database_update_error',
      error: error instanceof Error ? error.message : String(error)
    }, 'ProSe AV generation failed: Failed to update sequence number');
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Failed to update sequence number'
    });
  }

  const result: ProSeAuthenticationInfoResult = {
    authType: AuthType.EAP_AKA_PRIME,
    proseAuthenticationVectors: [proseVector],
    supi: supi,
    supportedFeatures: proseAuthRequest.supportedFeatures
  };

  auditLog('prose_av_generation_success', {
    supi: supi,
    serving_network: proseAuthRequest.servingNetworkName,
    relay_service_code: proseAuthRequest.relayServiceCode
  }, 'ProSe authentication vector generated successfully');

  return res.status(200).json(result);
});

export default router;

