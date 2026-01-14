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
  GbaAuthenticationInfoRequest,
  GbaAuthenticationInfoResult,
  GbaAuthType,
  ThreeGAkaAv,
  ProSeAuthenticationInfoRequest,
  ProSeAuthenticationInfoResult
} from '../types/nudm-ueau-types';
import { createNotFoundError, createInvalidParameterError, suciPattern } from '../types/common-types';
import {
  generateRand,
  milenage,
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
    auditLog('auth_vector_generation_failed', {
      identifier_type: 'suci',
      reason: 'suci_not_implemented'
    }, 'Auth vector generation failed: SUCI de-concealment not implemented');
    return res.status(501).json({
      type: 'urn:3gpp:error:not-implemented',
      title: 'Not Implemented',
      status: 501,
      detail: 'SUCI de-concealment is not yet implemented'
    });
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

  auditLog('key_access', {
    supi: supi,
    key_types: ['permanentKey', 'operatorKey'],
    purpose: 'auth_vector_generation'
  }, 'Accessed subscriber cryptographic keys for authentication');

  if (authRequest.resynchronizationInfo) {
    console.log('[UDM RESYNC] Resynchronization requested');
    auditLog('resynchronization_request', {
      supi: supi,
      rand: authRequest.resynchronizationInfo.rand
    }, 'Sequence number resynchronization requested');
    const kBuf = Buffer.from(permanentKey, 'hex');
    const opBuf = Buffer.from(operatorKey, 'hex');
    const randBuf = Buffer.from(authRequest.resynchronizationInfo.rand, 'hex');
    const autsBuf = Buffer.from(authRequest.resynchronizationInfo.auts, 'hex');
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
    const newSqnInt = (sqnMsInt + 32);
    sequenceNumber = newSqnInt.toString(16).padStart(12, '0').toUpperCase();
    console.log('[UDM RESYNC] Sequence number resynchronized');
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

  const authVector: Av5GHeAka = {
    avType: AvType.FIVE_G_HE_AKA,
    rand: rand,
    xresStar: xresStar,
    autn: autn,
    kausf: kausf
  };

  const newSqnInt = parseInt(sequenceNumber, 16) + 1;
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
    authType: AuthType.FIVE_G_AKA,
    authenticationVector: authVector,
    supi: supi
  };

  auditLog('auth_vector_generation_success', {
    supi: supi,
    serving_network: authRequest.servingNetworkName,
    ausf_instance: authRequest.ausfInstanceId
  }, 'Authentication vector generated successfully');

  return res.status(200).json(authResult);
});

router.get('/:supiOrSuci/security-information-rg', async (req: Request, res: Response) => {
  const { supiOrSuci } = req.params;

  let supi = supiOrSuci;

  if (suciPattern.test(supiOrSuci)) {
    return res.status(501).json({
      type: 'urn:3gpp:error:not-implemented',
      title: 'Not Implemented',
      status: 501,
      detail: 'SUCI de-concealment is not yet implemented'
    });
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

  const authInd = !!(permanentKey && operatorKey && sequenceNumber);

  const rgAuthCtx: RgAuthCtx = {
    authInd: authInd,
    supi: supi
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

  if (authEvent.success === undefined || authEvent.success === null) {
    return res.status(400).json(createInvalidParameterError('success is required'));
  }

  if (typeof authEvent.success !== 'boolean') {
    return res.status(400).json(createInvalidParameterError('success must be a boolean'));
  }

  if (!authEvent.timeStamp) {
    return res.status(400).json(createInvalidParameterError('timeStamp is required'));
  }

  if (!authEvent.authType) {
    return res.status(400).json(createInvalidParameterError('authType is required'));
  }

  if (!authEvent.servingNetworkName) {
    return res.status(400).json(createInvalidParameterError('servingNetworkName is required'));
  }

  if (!supi.startsWith('imsi-')) {
    return res.status(400).json(createInvalidParameterError('Invalid SUPI format, must start with imsi-'));
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

  const authEventId = randomUUID();

  const authEventRecord = {
    authEventId,
    supi,
    nfInstanceId: authEvent.nfInstanceId,
    success: authEvent.success,
    timeStamp: authEvent.timeStamp,
    authType: authEvent.authType,
    servingNetworkName: authEvent.servingNetworkName,
    authRemovalInd: authEvent.authRemovalInd ?? false,
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
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Failed to store authentication event'
    });
  }

  const location = `/nudm-ueau/v1/${supi}/auth-events/${authEventId}`;
  res.setHeader('Location', location);

  // Return the created auth event (201 Created)
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

  if (hssAuthRequest.numOfRequestedVectors < 1 || hssAuthRequest.numOfRequestedVectors > 32) {
    return res.status(400).json(createInvalidParameterError('numOfRequestedVectors must be between 1 and 32'));
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
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Missing authentication credentials for subscriber'
    });
  }

  // Generate authentication vectors
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

  // Validate request body
  if (!authEvent || typeof authEvent !== 'object') {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  // Validate required fields
  if (!authEvent.nfInstanceId) {
    return res.status(400).json(createInvalidParameterError('nfInstanceId is required'));
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

  if (!authEvent.authType) {
    return res.status(400).json(createInvalidParameterError('authType is required'));
  }

  if (!authEvent.servingNetworkName) {
    return res.status(400).json(createInvalidParameterError('servingNetworkName is required'));
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

  let existingAuthEvent;
  try {
    const authEventsCollection = getCollection<AuthEvent & { authEventId: string; supi: string }>('authEvents');
    existingAuthEvent = await authEventsCollection.findOne({ authEventId, supi });
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Database operation failed'
    });
  }

  if (!existingAuthEvent) {
    return res.status(404).json(createNotFoundError(`Auth event with ID ${authEventId} not found for SUPI ${supi}`));
  }

  try {
    const authEventsCollection = getCollection<AuthEvent & { authEventId: string; supi: string }>('authEvents');
    const updateResult = await authEventsCollection.updateOne(
      { authEventId, supi },
      {
        $set: {
          nfInstanceId: authEvent.nfInstanceId,
          success: authEvent.success,
          timeStamp: authEvent.timeStamp,
          authType: authEvent.authType,
          servingNetworkName: authEvent.servingNetworkName,
          authRemovalInd: authEvent.authRemovalInd ?? false,
          nfSetId: authEvent.nfSetId,
          resetIds: authEvent.resetIds,
          dataRestorationCallbackUri: authEvent.dataRestorationCallbackUri,
          udrRestartInd: authEvent.udrRestartInd ?? false,
          lastSynchronizationTime: authEvent.lastSynchronizationTime,
          nswoInd: authEvent.nswoInd ?? false
        }
      }
    );

    if (updateResult.modifiedCount === 0) {
      return res.status(500).json({
        type: 'urn:3gpp:error:internal-error',
        title: 'Internal Server Error',
        status: 500,
        detail: 'Failed to update auth event'
      });
    }
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Failed to update auth event'
    });
  }

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

  // Generate authentication vector for GBA
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

  const threeGAkaAv: ThreeGAkaAv = {
    rand: rand,
    xres: xres,
    autn: autn,
    ck: milenageOutput.ck.toString('hex').toUpperCase(),
    ik: milenageOutput.ik.toString('hex').toUpperCase()
  };

  // Update sequence number in database
  const newSqnInt = parseInt(sequenceNumber, 16) + 1;
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
    threeGAkaAv: threeGAkaAv,
    supportedFeatures: gbaAuthRequest.supportedFeatures
  };

  return res.status(200).json(result);
});

router.post('/:supiOrSuci/prose-security-information/generate-av', async (req: Request, res: Response) => {
  const { supiOrSuci } = req.params;
  const proseAuthRequest: ProSeAuthenticationInfoRequest = req.body;

  // Validate request body
  if (!proseAuthRequest || typeof proseAuthRequest !== 'object' || Array.isArray(proseAuthRequest)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  // Validate required fields
  if (!proseAuthRequest.servingNetworkName) {
    return res.status(400).json(createInvalidParameterError('servingNetworkName is required'));
  }

  if (!proseAuthRequest.relayServiceCode) {
    return res.status(400).json(createInvalidParameterError('relayServiceCode is required'));
  }

  let supi = supiOrSuci;

  // Handle SUCI (not implemented)
  if (suciPattern.test(supiOrSuci)) {
    return res.status(501).json({
      type: 'urn:3gpp:error:not-implemented',
      title: 'Not Implemented',
      status: 501,
      detail: 'SUCI de-concealment is not yet implemented'
    });
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

  // Generate authentication vector for ProSe (EAP-AKA')
  // Per 3GPP spec, UDM should send only one vector in the array
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

  // Compute CK' and IK' for EAP-AKA'
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

  // Update sequence number in database
  const newSqnInt = parseInt(sequenceNumber, 16) + 1;
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

  const result: ProSeAuthenticationInfoResult = {
    authType: AuthType.EAP_AKA_PRIME,
    proseAuthenticationVectors: [proseVector],
    supi: supi,
    supportedFeatures: proseAuthRequest.supportedFeatures
  };

  return res.status(200).json(result);
});

export default router;

