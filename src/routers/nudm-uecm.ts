import { Router, Request, Response } from 'express';
import { getCollection } from '../db/mongodb';
import {
  RegistrationDataSets,
  RegistrationDataSetName,
  Amf3GppAccessRegistration,
  Amf3GppAccessRegistrationModification,
  AmfNon3GppAccessRegistration,
  AmfNon3GppAccessRegistrationModification,
  SmfRegistration,
  SmfRegistrationInfo,
  SmfRegistrationModification,
  SmsfRegistration,
  SmsfRegistrationModification,
  IpSmGwRegistration,
  NwdafRegistrationInfo,
  NwdafRegistration,
  NwdafRegistrationModification,
  RoutingInfoSmRequest,
  RoutingInfoSmResponse,
  IpSmGwInfo,
  AmfDeregInfo,
  DeregistrationData,
  PeiUpdateInfo,
  RoamingInfoUpdate,
  TriggerRequest,
  PcscfRestorationNotification,
  LocationInfo,
  RegistrationLocationInfo
} from '../types/nudm-uecm-types';
import {
  validateUeIdentity,
  createInvalidParameterError,
  createMissingParameterError,
  createNotFoundError,
  createInternalError,
  stripInternalFields,
  Snssai,
  Dnn,
  deepMerge,
  PatchResult,
  AccessType,
  PlmnId,
  RatType,
  createNotImplementedError
} from '../types/common-types';
import { resolveGpsiToSupi } from '../db/sdm-db';
import logger from '../utils/logger';

const router = Router();

interface SmfRegistrationQuery {
  ueId: string;
  'singleNssai.sst'?: number;
  'singleNssai.sd'?: string;
  dnn?: string;
}

interface AmfRegistrationQuery {
  ueId: string;
  servingPlmn?: PlmnId;
}

interface RoamingInfoUpdateFields {
  servingPlmn: PlmnId;
  roaming?: boolean;
}

interface NwdafRegistrationQuery {
  ueId: string;
  analyticsIds?: { $in: string[] };
}

interface Amf3GppAccessRegistrationWithRoaming extends Amf3GppAccessRegistration {
  servingPlmn?: PlmnId;
  roaming?: boolean;
}

const notImplemented = (req: Request, res: Response) => {
  res.status(501).json(createNotImplementedError('This endpoint is not yet implemented'));
};

router.get('/:ueId/registrations', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'msisdn', 'extid'], true)) {
    return res.status(400).type('application/problem+json').json(createInvalidParameterError('Invalid ueId format'));
  }

  const registrationDatasetNamesParam = req.query['registration-dataset-names'];
  if (!registrationDatasetNamesParam) {
    return res.status(400).type('application/problem+json').json(createMissingParameterError('Missing required query parameter: registration-dataset-names'));
  }

  let registrationDatasetNames: string[];
  if (typeof registrationDatasetNamesParam === 'string') {
    registrationDatasetNames = registrationDatasetNamesParam.split(',');
  } else if (Array.isArray(registrationDatasetNamesParam)) {
    registrationDatasetNames = registrationDatasetNamesParam as string[];
  } else {
    return res.status(400).type('application/problem+json').json(createInvalidParameterError('Invalid registration-dataset-names format'));
  }

  registrationDatasetNames = [...new Set(registrationDatasetNames)];

  if (registrationDatasetNames.length < 2) {
    return res.status(400).type('application/problem+json').json(createInvalidParameterError('registration-dataset-names must contain at least 2 unique values'));
  }

  const validDatasetNames = Object.values(RegistrationDataSetName);
  const invalidNames = registrationDatasetNames.filter(name => !validDatasetNames.includes(name as RegistrationDataSetName));

  if (invalidNames.length > 0) {
    return res.status(400).type('application/problem+json').json(createInvalidParameterError(`Invalid registration-dataset-names: ${invalidNames.join(', ')}`));
  }

  let singleNssai: Snssai | undefined;
  const singleNssaiParam = req.query['single-nssai'];
  if (singleNssaiParam) {
    try {
      if (typeof singleNssaiParam === 'string') {
        singleNssai = JSON.parse(singleNssaiParam) as Snssai;
      } else {
        singleNssai = singleNssaiParam as unknown as Snssai;
      }

      if (typeof singleNssai.sst !== 'number' || singleNssai.sst < 0 || singleNssai.sst > 255) {
        return res.status(400).type('application/problem+json').json(createInvalidParameterError('Invalid single-nssai: sst must be a number between 0 and 255'));
      }

      if (singleNssai.sd !== undefined && typeof singleNssai.sd !== 'string') {
        return res.status(400).type('application/problem+json').json(createInvalidParameterError('Invalid single-nssai: sd must be a string'));
      }
    } catch (error) {
      return res.status(400).type('application/problem+json').json(createInvalidParameterError('Invalid single-nssai format'));
    }
  }

  const dnn = req.query['dnn'] as Dnn | undefined;

  try {
    const registrationDataSets: RegistrationDataSets = {};

    for (const datasetName of registrationDatasetNames) {
      switch (datasetName) {
        case RegistrationDataSetName.AMF_3GPP:
          {
            const collection = await getCollection('amf3GppRegistrations');
            const doc = await collection.findOne({ ueId });
            if (doc) {
              registrationDataSets.amf3Gpp = stripInternalFields<Amf3GppAccessRegistration>(doc as Record<string, any>);
            }
          }
          break;

        case RegistrationDataSetName.AMF_NON_3GPP:
          {
            const collection = await getCollection('amfNon3GppRegistrations');
            const doc = await collection.findOne({ ueId });
            if (doc) {
              registrationDataSets.amfNon3Gpp = stripInternalFields<AmfNon3GppAccessRegistration>(doc as Record<string, any>);
            }
          }
          break;

        case RegistrationDataSetName.SMF_PDU_SESSIONS:
          {
            const collection = await getCollection('smfRegistrations');
            const query: SmfRegistrationQuery = { ueId };

            if (singleNssai) {
              query['singleNssai.sst'] = singleNssai.sst;
              if (singleNssai.sd !== undefined) {
                query['singleNssai.sd'] = singleNssai.sd;
              }
            }

            if (dnn) {
              query.dnn = dnn;
            }

            const docs = await collection.find(query).toArray();
            if (docs.length > 0) {
              registrationDataSets.smfRegistration = {
                smfRegistrationList: docs.map(d => stripInternalFields<SmfRegistration>(d as Record<string, any>))
              };
            }
          }
          break;

        case RegistrationDataSetName.SMSF_3GPP:
          {
            const collection = await getCollection('smsf3GppRegistrations');
            const doc = await collection.findOne({ ueId });
            if (doc) {
              registrationDataSets.smsf3Gpp = stripInternalFields<SmsfRegistration>(doc as Record<string, any>);
            }
          }
          break;

        case RegistrationDataSetName.SMSF_NON_3GPP:
          {
            const collection = await getCollection('smsfNon3GppRegistrations');
            const doc = await collection.findOne({ ueId });
            if (doc) {
              registrationDataSets.smsfNon3Gpp = stripInternalFields<SmsfRegistration>(doc as Record<string, any>);
            }
          }
          break;

        case RegistrationDataSetName.IP_SM_GW:
          {
            const collection = await getCollection('ipSmGwRegistrations');
            const doc = await collection.findOne({ ueId });
            if (doc) {
              registrationDataSets.ipSmGw = stripInternalFields<IpSmGwRegistration>(doc as Record<string, any>);
            }
          }
          break;

        case RegistrationDataSetName.NWDAF:
          {
            const collection = await getCollection('nwdafRegistrations');
            const docs = await collection.find({ ueId }).toArray();
            if (docs.length > 0) {
              registrationDataSets.nwdafRegistration = {
                nwdafRegistrationList: docs.map(d => stripInternalFields<NwdafRegistration>(d as Record<string, any>))
              };
            }
          }
          break;
      }
    }

    if (Object.keys(registrationDataSets).length === 0) {
      return res.status(404).type('application/problem+json').json(createNotFoundError('No registration data found for the specified UE'));
    }

    return res.status(200).json(registrationDataSets);
  } catch (error) {
    logger.error('Error retrieving registration data', { error });
    return res.status(500).type('application/problem+json').json(createInternalError('An error occurred while retrieving registration data'));
  }
});

router.post('/:ueId/registrations/send-routing-info-sm', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'msisdn', 'extid'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const requestBody = req.body as RoutingInfoSmRequest;

  if (!requestBody || typeof requestBody !== 'object') {
    return res.status(400).json(createInvalidParameterError('Invalid request body'));
  }

  try {
    const supi = await resolveGpsiToSupi(ueId);
    if (!supi) {
      return res.status(404).json(createNotFoundError('Unable to resolve UE identity'));
    }

    const smsf3GppCollection = await getCollection('smsf3GppRegistrations');
    const smsfNon3GppCollection = await getCollection('smsfNon3GppRegistrations');
    const ipSmGwCollection = await getCollection('ipSmGwRegistrations');

    const smsf3GppDoc = await smsf3GppCollection.findOne({ ueId: supi });
    const smsfNon3GppDoc = await smsfNon3GppCollection.findOne({ ueId: supi });
    const ipSmGwDoc = await ipSmGwCollection.findOne({ ueId: supi });

    if (!smsf3GppDoc && !smsfNon3GppDoc && !ipSmGwDoc) {
      return res.status(404).json(createNotFoundError('No SMS routing information found for the specified UE'));
    }

    const response: RoutingInfoSmResponse = {
      supi
    };

    if (smsf3GppDoc) {
      response.smsf3Gpp = stripInternalFields<SmsfRegistration>(smsf3GppDoc as Record<string, any>);
    }

    if (smsfNon3GppDoc) {
      response.smsfNon3Gpp = stripInternalFields<SmsfRegistration>(smsfNon3GppDoc as Record<string, any>);
    }

    if (ipSmGwDoc && requestBody.ipSmGwInd === true) {
      const cleanReg = stripInternalFields<IpSmGwRegistration>(ipSmGwDoc as Record<string, any>);
      const ipSmGwInfo: IpSmGwInfo = {
        ipSmGwRegistration: cleanReg
      };
      const docAny = ipSmGwDoc as Record<string, any>;
      if (docAny.ipSmGwGuidance) {
        ipSmGwInfo.ipSmGwGuidance = docAny.ipSmGwGuidance;
      }
      response.ipSmGw = ipSmGwInfo;
    }

    return res.status(200).json(response);
  } catch (error) {
    logger.error('Error retrieving SMS routing information', { error });
    return res.status(500).json(createInternalError('An error occurred while retrieving SMS routing information'));
  }
});

router.put('/:ueId/registrations/amf-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const registration = req.body as Amf3GppAccessRegistration;

  if (!registration.amfInstanceId) {
    return res.status(400).json(createMissingParameterError('Missing required field: amfInstanceId'));
  }

  if (!registration.deregCallbackUri) {
    return res.status(400).json(createMissingParameterError('Missing required field: deregCallbackUri'));
  }

  if (!registration.guami) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami'));
  }

  if (!registration.guami.plmnId) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami.plmnId'));
  }

  if (!registration.guami.plmnId.mcc) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami.plmnId.mcc'));
  }

  if (!registration.guami.plmnId.mnc) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami.plmnId.mnc'));
  }

  if (!registration.guami.amfId) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami.amfId'));
  }

  if (!registration.ratType) {
    return res.status(400).json(createMissingParameterError('Missing required field: ratType'));
  }

  if (!Object.values(RatType).includes(registration.ratType)) {
    return res.status(400).json(createInvalidParameterError('Invalid ratType value'));
  }

  try {
    const collection = await getCollection('amf3GppRegistrations');
    const existingReg = await collection.findOne({ ueId });

    const registrationData = {
      ...registration,
      ueId
    };

    const isSameAmf = existingReg && existingReg.amfInstanceId === registration.amfInstanceId;

    await collection.replaceOne({ ueId }, registrationData, { upsert: true });

    if (isSameAmf) {
      return res.status(200).json(registration);
    } else {
      const location = `${req.protocol}://${req.get('host')}/nudm-uecm/v1/${ueId}/registrations/amf-3gpp-access`;
      return res.status(201)
        .header('Location', location)
        .json(registration);
    }
  } catch (error) {
    logger.error('Error creating/updating AMF 3GPP registration', { error });
    return res.status(500).json(createInternalError('An error occurred while creating/updating AMF 3GPP registration'));
  }
});

router.patch('/:ueId/registrations/amf-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const body = req.body;

  if (!body || !body.guami) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami'));
  }

  if (!body.guami.plmnId) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami.plmnId'));
  }

  if (!body.guami.plmnId.mcc) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami.plmnId.mcc'));
  }

  if (!body.guami.plmnId.mnc) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami.plmnId.mnc'));
  }

  if (!body.guami.amfId) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami.amfId'));
  }

  const allowedFields = ['guami', 'purgeFlag', 'pei', 'imsVoPs', 'backupAmfInfo', 'epsInterworkingInfo', 'ueSrvccCapability', 'ueMINTCapability'];
  const modification: Partial<Amf3GppAccessRegistrationModification> = {};
  for (const field of allowedFields) {
    if (field in body) {
      (modification as any)[field] = body[field];
    }
  }

  try {
    const collection = await getCollection('amf3GppRegistrations');
    const existingReg = await collection.findOne({ ueId }) as (Amf3GppAccessRegistration & { _id?: any, ueId?: string }) | null;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'AMF 3GPP registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    const storedGuami = existingReg.guami;
    const incomingGuami = modification.guami!;
    if (
      storedGuami.plmnId.mcc !== incomingGuami.plmnId.mcc ||
      storedGuami.plmnId.mnc !== incomingGuami.plmnId.mnc ||
      storedGuami.amfId !== incomingGuami.amfId
    ) {
      return res.status(403).json({
        type: 'urn:3gpp:error:application',
        title: 'Forbidden',
        status: 403,
        detail: 'GUAMI mismatch with existing registration',
        cause: 'SERVING_NF_NOT_REGISTERED'
      });
    }

    const { _id, ueId: storedUeId, ...cleanReg } = existingReg;
    const updatedReg = deepMerge(cleanReg, modification);
    updatedReg.ueId = storedUeId;

    await collection.replaceOne({ ueId }, updatedReg);

    return res.status(204).send();
  } catch (error) {
    logger.error('Error updating AMF 3GPP registration', { error });
    return res.status(500).json(createInternalError('An error occurred while updating AMF 3GPP registration'));
  }
});

router.get('/:ueId/registrations/amf-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  try {
    const collection = await getCollection('amf3GppRegistrations');
    const registration = await collection.findOne({ ueId }) as Amf3GppAccessRegistration | null;

    if (!registration) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'AMF 3GPP registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    return res.status(200).json(stripInternalFields<Amf3GppAccessRegistration>(registration as any));
  } catch (error) {
    logger.error('Error retrieving AMF 3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while retrieving AMF 3GPP registration'
    });
  }
});

router.post('/:ueId/registrations/amf-3gpp-access/dereg-amf', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const deregInfo = req.body as AmfDeregInfo;

  if (!deregInfo || typeof deregInfo !== 'object') {
    return res.status(400).json(createInvalidParameterError('Invalid request body'));
  }

  if (!deregInfo.deregReason || typeof deregInfo.deregReason !== 'string') {
    return res.status(400).json(createMissingParameterError('Missing required field: deregReason'));
  }

  try {
    const collection = await getCollection('amf3GppRegistrations');
    const existingReg = await collection.findOne({ ueId });

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'AMF 3GPP registration context not found',
        cause: 'USER_NOT_FOUND'
      });
    }

    const { deregCallbackUri } = existingReg as unknown as Amf3GppAccessRegistration;

    if (!deregCallbackUri) {
      logger.error('No deregCallbackUri in AMF 3GPP registration', { ueId });
      return res.status(500).json(createInternalError('No deregCallbackUri stored for this registration'));
    }

    const deregData: DeregistrationData = {
      deregReason: deregInfo.deregReason,
      accessType: AccessType.THREE_GPP_ACCESS
    };

    try {
      const callbackResponse = await fetch(deregCallbackUri, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(deregData)
      });

      if (!callbackResponse.ok) {
        logger.warn('AMF deregistration callback returned non-success', {
          ueId,
          uri: deregCallbackUri,
          status: callbackResponse.status
        });
      }
    } catch (callbackError) {
      logger.error('Failed to send deregistration callback to AMF', {
        ueId,
        uri: deregCallbackUri,
        error: callbackError
      });
    }

    return res.status(204).send();
  } catch (error) {
    logger.error('Error triggering AMF deregistration', { error });
    return res.status(500).json(createInternalError('An error occurred while triggering AMF deregistration'));
  }
});

router.post('/:ueId/registrations/amf-3gpp-access/pei-update', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const peiUpdateInfo = req.body as PeiUpdateInfo;

  if (!peiUpdateInfo || typeof peiUpdateInfo !== 'object') {
    return res.status(400).json(createInvalidParameterError('Invalid request body'));
  }

  if (!peiUpdateInfo.pei || typeof peiUpdateInfo.pei !== 'string') {
    return res.status(400).json(createMissingParameterError('Missing required field: pei'));
  }

  try {
    const collection = await getCollection('amf3GppRegistrations');
    const existingReg = await collection.findOne({ ueId }) as (Amf3GppAccessRegistration & { ueId?: string }) | null;

    if (!existingReg) {
      return res.status(404).json(createNotFoundError('AMF 3GPP registration context not found'));
    }

    const incomingGuami = req.headers['x-guami'] ? JSON.parse(req.headers['x-guami'] as string) : null;
    if (incomingGuami) {
      const storedGuami = existingReg.guami;
      if (
        storedGuami.plmnId.mcc !== incomingGuami.plmnId?.mcc ||
        storedGuami.plmnId.mnc !== incomingGuami.plmnId?.mnc ||
        storedGuami.amfId !== incomingGuami.amfId
      ) {
        return res.status(403).json({
          type: 'urn:3gpp:error:application',
          title: 'Forbidden',
          status: 403,
          detail: 'GUAMI mismatch with existing registration',
          cause: 'SERVING_NF_NOT_REGISTERED'
        });
      }
    }

    const oldPei = existingReg.pei;

    await collection.updateOne(
      { ueId },
      { $set: { pei: peiUpdateInfo.pei } }
    );

    if (oldPei !== peiUpdateInfo.pei) {
      notifyPeiChange(ueId, peiUpdateInfo.pei).catch(err => {
        logger.error('Failed to send PEI change notifications', { ueId, error: err });
      });
    }

    return res.status(204).send();
  } catch (error) {
    logger.error('Error updating PEI in AMF 3GPP registration', { error });
    return res.status(500).json(createInternalError('An error occurred while updating PEI'));
  }
});

async function notifyPeiChange(ueId: string, newPei: string): Promise<void> {
  const eeCollection = await getCollection('ee-subscriptions');
  const subscriptions = await eeCollection.find({
    ueIdentity: ueId,
    [`monitoringConfigurations`]: { $exists: true }
  }).toArray();

  for (const sub of subscriptions) {
    const configs = (sub as any).monitoringConfigurations as Record<string, any>;
    if (!configs) continue;

    for (const [refId, config] of Object.entries(configs)) {
      if (config.eventType !== 'CHANGE_OF_SUPI_PEI_ASSOCIATION') continue;

      const callbackUri = (sub as any).callbackReference;
      if (!callbackUri) continue;

      const report = {
        eventNotifs: [{
          event: 'CHANGE_OF_SUPI_PEI_ASSOCIATION',
          referenceId: parseInt(refId) || 0,
          eventType: 'CHANGE_OF_SUPI_PEI_ASSOCIATION',
          timeStamp: new Date().toISOString(),
          report: { newPei }
        }]
      };

      try {
        const response = await fetch(callbackUri, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(report)
        });
        if (!response.ok) {
          logger.warn('EE notification callback returned non-success', {
            ueId, uri: callbackUri, status: response.status
          });
        }
      } catch (err) {
        logger.error('Failed to send EE notification callback', {
          ueId, uri: callbackUri, error: err
        });
      }
    }
  }
}

router.post('/:ueId/registrations/amf-3gpp-access/roaming-info-update', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const roamingInfoUpdate = req.body as RoamingInfoUpdate;

  if (!roamingInfoUpdate || typeof roamingInfoUpdate !== 'object' || Array.isArray(roamingInfoUpdate)) {
    return res.status(400).json(createInvalidParameterError('Invalid request body'));
  }

  if (!roamingInfoUpdate.servingPlmn) {
    return res.status(400).json(createMissingParameterError('Missing required field: servingPlmn'));
  }

  if (!roamingInfoUpdate.servingPlmn.mcc || !roamingInfoUpdate.servingPlmn.mnc) {
    return res.status(400).json(createInvalidParameterError('servingPlmn must contain mcc and mnc'));
  }

  if (!/^\d{3}$/.test(roamingInfoUpdate.servingPlmn.mcc) || !/^\d{2,3}$/.test(roamingInfoUpdate.servingPlmn.mnc)) {
    return res.status(400).json(createInvalidParameterError('mcc must be 3 digits and mnc must be 2-3 digits'));
  }

  if (roamingInfoUpdate.roaming !== undefined && typeof roamingInfoUpdate.roaming !== 'boolean') {
    return res.status(400).json(createInvalidParameterError('roaming must be a boolean'));
  }

  try {
    const collection = await getCollection('amf3GppRegistrations');
    const existingReg = await collection.findOne({ ueId }) as Amf3GppAccessRegistrationWithRoaming | null;

    if (!existingReg) {
      return res.status(404).json(createNotFoundError('AMF 3GPP registration context not found'));
    }

    const hasExistingRoamingInfo = existingReg.servingPlmn !== undefined;

    const updateFields: RoamingInfoUpdateFields = {
      servingPlmn: roamingInfoUpdate.servingPlmn
    };

    if (roamingInfoUpdate.roaming !== undefined) {
      updateFields.roaming = roamingInfoUpdate.roaming;
    }

    await collection.updateOne(
      { ueId },
      { $set: updateFields }
    );

    if (!hasExistingRoamingInfo) {
      const location = `${req.protocol}://${req.get('host')}/nudm-uecm/v1/${ueId}/registrations/amf-3gpp-access/roaming-info-update`;
      return res.status(201)
        .header('Location', location)
        .json(roamingInfoUpdate);
    } else {
      return res.status(204).send();
    }
  } catch (error) {
    logger.error('Error updating roaming information in AMF 3GPP registration', { error });
    return res.status(500).json(createInternalError('An error occurred while updating roaming information'));
  }
});

router.put('/:ueId/registrations/amf-non-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const registration = req.body as AmfNon3GppAccessRegistration;

  if (!registration.amfInstanceId) {
    return res.status(400).json(createMissingParameterError('Missing required field: amfInstanceId'));
  }

  if (!registration.deregCallbackUri) {
    return res.status(400).json(createMissingParameterError('Missing required field: deregCallbackUri'));
  }

  if (!registration.guami) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami'));
  }

  if (!registration.guami.plmnId) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami.plmnId'));
  }

  if (!registration.guami.plmnId.mcc) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami.plmnId.mcc'));
  }

  if (!registration.guami.plmnId.mnc) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami.plmnId.mnc'));
  }

  if (!registration.guami.amfId) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami.amfId'));
  }

  if (!registration.ratType) {
    return res.status(400).json(createMissingParameterError('Missing required field: ratType'));
  }

  if (!Object.values(RatType).includes(registration.ratType)) {
    return res.status(400).json(createInvalidParameterError('Invalid ratType value'));
  }

  if (!registration.imsVoPs) {
    return res.status(400).json(createMissingParameterError('Missing required field: imsVoPs'));
  }

  try {
    const collection = await getCollection('amfNon3GppRegistrations');
    const existingReg = await collection.findOne({ ueId });

    const registrationData = {
      ...registration,
      ueId
    };

    const isSameAmf = existingReg && existingReg.amfInstanceId === registration.amfInstanceId;

    await collection.replaceOne({ ueId }, registrationData, { upsert: true });

    if (isSameAmf) {
      return res.status(200).json(registration);
    } else {
      const location = `${req.protocol}://${req.get('host')}/nudm-uecm/v1/${ueId}/registrations/amf-non-3gpp-access`;
      return res.status(201)
        .header('Location', location)
        .json(registration);
    }
  } catch (error) {
    logger.error('Error creating/updating AMF non-3GPP registration', { error });
    return res.status(500).json(createInternalError('An error occurred while creating/updating AMF non-3GPP registration'));
  }
});

router.patch('/:ueId/registrations/amf-non-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const modification = req.body as AmfNon3GppAccessRegistrationModification;

  if (!modification.guami) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami'));
  }

  const supportedFeatures = req.query['supported-features'] as string | undefined;

  try {
    const collection = await getCollection('amfNon3GppRegistrations');
    const existingReg = await collection.findOne({ ueId }) as AmfNon3GppAccessRegistration | null;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'AMF non-3GPP registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    const updatedReg = deepMerge(existingReg, modification);

    await collection.replaceOne({ ueId }, updatedReg);

    return res.status(204).send();
  } catch (error) {
    logger.error('Error updating AMF non-3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while updating AMF non-3GPP registration'
    });
  }
});

router.get('/:ueId/registrations/amf-non-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'msisdn', 'extid'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  try {
    const collection = await getCollection('amfNon3GppRegistrations');
    const registration = await collection.findOne({ ueId }) as AmfNon3GppAccessRegistration | null;

    if (!registration) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'AMF non-3GPP registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    return res.status(200).json(registration);
  } catch (error) {
    logger.error('Error retrieving AMF non-3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while retrieving AMF non-3GPP registration'
    });
  }
});

router.get('/:ueId/registrations/smf-registrations', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'msisdn', 'extid'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const supportedFeatures = req.query['supported-features'] as string | undefined;

  let singleNssai: Snssai | undefined;
  const singleNssaiParam = req.query['single-nssai'];
  if (singleNssaiParam) {
    try {
      if (typeof singleNssaiParam === 'string') {
        singleNssai = JSON.parse(singleNssaiParam) as Snssai;
      } else {
        singleNssai = singleNssaiParam as unknown as Snssai;
      }
      
      if (typeof singleNssai.sst !== 'number' || singleNssai.sst < 0 || singleNssai.sst > 255) {
        return res.status(400).json(createInvalidParameterError('Invalid single-nssai: sst must be a number between 0 and 255'));
      }
      
      if (singleNssai.sd !== undefined && typeof singleNssai.sd !== 'string') {
        return res.status(400).json(createInvalidParameterError('Invalid single-nssai: sd must be a string'));
      }
    } catch (error) {
      return res.status(400).json(createInvalidParameterError('Invalid single-nssai format'));
    }
  }

  const dnn = req.query['dnn'] as Dnn | undefined;

  try {
    const collection = await getCollection('smfRegistrations');
    const query: SmfRegistrationQuery = { ueId };

    if (singleNssai) {
      query['singleNssai.sst'] = singleNssai.sst;
      if (singleNssai.sd !== undefined) {
        query['singleNssai.sd'] = singleNssai.sd;
      }
    }

    if (dnn) {
      query.dnn = dnn;
    }

    const registrations = await collection.find(query).toArray() as unknown as SmfRegistration[];

    if (registrations.length === 0) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'No SMF registration found for the specified UE',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    const smfRegistrationInfo: SmfRegistrationInfo = {
      smfRegistrationList: registrations
    };

    return res.status(200).json(smfRegistrationInfo);
  } catch (error) {
    logger.error('Error retrieving SMF registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while retrieving SMF registration'
    });
  }
});

router.put('/:ueId/registrations/smf-registrations/:pduSessionId', async (req: Request, res: Response) => {
  const { ueId, pduSessionId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const pduSessionIdNum = parseInt(pduSessionId, 10);
  if (isNaN(pduSessionIdNum) || pduSessionIdNum < 0 || pduSessionIdNum > 255) {
    return res.status(400).json(createInvalidParameterError('Invalid pduSessionId'));
  }

  const registration = req.body as SmfRegistration;

  if (!registration.smfInstanceId) {
    return res.status(400).json(createMissingParameterError('Missing required field: smfInstanceId'));
  }

  if (registration.pduSessionId === undefined || registration.pduSessionId !== pduSessionIdNum) {
    return res.status(400).json(createInvalidParameterError('pduSessionId in body must match path parameter'));
  }

  if (!registration.singleNssai) {
    return res.status(400).json(createMissingParameterError('Missing required field: singleNssai'));
  }

  if (!registration.plmnId) {
    return res.status(400).json(createMissingParameterError('Missing required field: plmnId'));
  }

  try {
    const collection = await getCollection('smfRegistrations');
    const existingReg = await collection.findOne({ ueId, pduSessionId: pduSessionIdNum }) as SmfRegistration | null;

    const registrationData = {
      ...registration,
      ueId,
      pduSessionId: pduSessionIdNum
    };

    if (!existingReg) {
      await collection.insertOne(registrationData);
      const location = `${req.protocol}://${req.get('host')}/nudm-uecm/v1/${ueId}/registrations/smf-registrations/${pduSessionId}`;
      return res.status(201)
        .header('Location', location)
        .json(registrationData);
    } else {
      await collection.replaceOne({ ueId, pduSessionId: pduSessionIdNum }, registrationData);
      return res.status(200).json(registrationData);
    }
  } catch (error) {
    logger.error('Error creating/updating SMF registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while creating/updating SMF registration'
    });
  }
});

router.delete('/:ueId/registrations/smf-registrations/:pduSessionId', async (req: Request, res: Response) => {
  const { ueId, pduSessionId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const pduSessionIdNum = parseInt(pduSessionId, 10);
  if (isNaN(pduSessionIdNum) || pduSessionIdNum < 0 || pduSessionIdNum > 255) {
    return res.status(400).json(createInvalidParameterError('Invalid pduSessionId'));
  }

  const smfSetId = req.query['smf-set-id'] as string | undefined;
  const smfInstanceId = req.query['smf-instance-id'] as string | undefined;

  try {
    const collection = await getCollection('smfRegistrations');
    const existingReg = await collection.findOne({ ueId, pduSessionId: pduSessionIdNum }) as SmfRegistration | null;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'SMF registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    if (smfSetId && existingReg.smfSetId !== smfSetId) {
      return res.status(422).json({
        type: 'urn:3gpp:error:application',
        title: 'Unprocessable Request',
        status: 422,
        detail: 'SMF Set ID does not match the registered SMF Set ID'
      });
    }

    if (!smfSetId && smfInstanceId && existingReg.smfInstanceId !== smfInstanceId) {
      return res.status(422).json({
        type: 'urn:3gpp:error:application',
        title: 'Unprocessable Request',
        status: 422,
        detail: 'SMF Instance ID does not match the registered SMF Instance ID'
      });
    }

    await collection.deleteOne({ ueId, pduSessionId: pduSessionIdNum });

    return res.status(204).send();
  } catch (error) {
    logger.error('Error deleting SMF registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while deleting SMF registration'
    });
  }
});

router.get('/:ueId/registrations/smf-registrations/:pduSessionId', async (req: Request, res: Response) => {
  const { ueId, pduSessionId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'msisdn', 'extid'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const pduSessionIdNum = parseInt(pduSessionId, 10);
  if (isNaN(pduSessionIdNum) || pduSessionIdNum < 0 || pduSessionIdNum > 255) {
    return res.status(400).json(createInvalidParameterError('Invalid pduSessionId'));
  }

  try {
    const collection = await getCollection('smfRegistrations');
    const registration = await collection.findOne({ ueId, pduSessionId: pduSessionIdNum }) as SmfRegistration | null;

    if (!registration) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'SMF registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    return res.status(200).json(registration);
  } catch (error) {
    logger.error('Error retrieving SMF registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while retrieving SMF registration'
    });
  }
});

router.patch('/:ueId/registrations/smf-registrations/:pduSessionId', async (req: Request, res: Response) => {
  const { ueId, pduSessionId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const pduSessionIdNum = parseInt(pduSessionId, 10);
  if (isNaN(pduSessionIdNum) || pduSessionIdNum < 0 || pduSessionIdNum > 255) {
    return res.status(400).json(createInvalidParameterError('Invalid pduSessionId'));
  }

  const modification = req.body as SmfRegistrationModification;

  if (!modification.smfInstanceId) {
    return res.status(400).json(createMissingParameterError('Missing required field: smfInstanceId'));
  }

  const supportedFeatures = req.query['supported-features'] as string | undefined;

  try {
    const collection = await getCollection('smfRegistrations');
    const existingReg = await collection.findOne({ ueId, pduSessionId: pduSessionIdNum }) as SmfRegistration | null;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'SMF registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    const updatedReg = deepMerge(existingReg, modification);

    await collection.replaceOne({ ueId, pduSessionId: pduSessionIdNum }, updatedReg);

    return res.status(204).send();
  } catch (error) {
    logger.error('Error updating SMF registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while updating SMF registration'
    });
  }
});

router.put('/:ueId/registrations/smsf-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const registration = req.body as SmsfRegistration;

  if (!registration.smsfInstanceId) {
    return res.status(400).json(createMissingParameterError('Missing required field: smsfInstanceId'));
  }

  if (!registration.plmnId) {
    return res.status(400).json(createMissingParameterError('Missing required field: plmnId'));
  }

  if (!registration.plmnId.mcc || !registration.plmnId.mnc) {
    return res.status(400).json(createInvalidParameterError('plmnId must contain mcc and mnc'));
  }

  try {
    const collection = await getCollection('smsf3GppRegistrations');
    const existingReg = await collection.findOne({ ueId });

    const registrationData = {
      ...registration,
      ueId
    };

    if (!existingReg) {
      await collection.insertOne(registrationData);
      const location = `${req.protocol}://${req.get('host')}/nudm-uecm/v1/${ueId}/registrations/smsf-3gpp-access`;
      return res.status(201)
        .header('Location', location)
        .json(registrationData);
    } else {
      await collection.replaceOne({ ueId }, registrationData);
      return res.status(200).json(registrationData);
    }
  } catch (error) {
    logger.error('Error creating/updating SMSF 3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while creating/updating SMSF 3GPP registration'
    });
  }
});

router.delete('/:ueId/registrations/smsf-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const smsfSetId = req.query['smsf-set-id'] as string | undefined;

  try {
    const collection = await getCollection('smsf3GppRegistrations');
    const existingReg = await collection.findOne({ ueId }) as SmsfRegistration | null;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'SMSF 3GPP registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    if (smsfSetId && existingReg.smsfSetId !== smsfSetId) {
      return res.status(422).json({
        type: 'urn:3gpp:error:application',
        title: 'Unprocessable Request',
        status: 422,
        detail: 'SMSF Set ID does not match the registered SMSF Set ID'
      });
    }

    await collection.deleteOne({ ueId });

    return res.status(204).send();
  } catch (error) {
    logger.error('Error deleting SMSF 3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while deleting SMSF 3GPP registration'
    });
  }
});

router.get('/:ueId/registrations/smsf-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['msisdn', 'extid'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const supportedFeatures = req.query['supported-features'] as string | undefined;

  try {
    const collection = await getCollection('smsf3GppRegistrations');
    const registration = await collection.findOne({ ueId }) as SmsfRegistration | null;

    if (!registration) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'SMSF 3GPP registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    return res.status(200).json(registration);
  } catch (error) {
    logger.error('Error retrieving SMSF 3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while retrieving SMSF 3GPP registration'
    });
  }
});

router.patch('/:ueId/registrations/smsf-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const modification = req.body as SmsfRegistrationModification;

  if (!modification.smsfInstanceId) {
    return res.status(400).json(createMissingParameterError('Missing required field: smsfInstanceId'));
  }

  const supportedFeatures = req.query['supported-features'] as string | undefined;

  try {
    const collection = await getCollection('smsf3GppRegistrations');
    const existingReg = await collection.findOne({ ueId }) as SmsfRegistration | null;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'SMSF 3GPP registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    const updatedReg = deepMerge(existingReg, modification);

    await collection.replaceOne({ ueId }, updatedReg);

    return res.status(204).send();
  } catch (error) {
    logger.error('Error updating SMSF 3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while updating SMSF 3GPP registration'
    });
  }
});

router.put('/:ueId/registrations/smsf-non-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const registration = req.body as SmsfRegistration;

  if (!registration.smsfInstanceId) {
    return res.status(400).json(createMissingParameterError('Missing required field: smsfInstanceId'));
  }

  if (!registration.plmnId) {
    return res.status(400).json(createMissingParameterError('Missing required field: plmnId'));
  }

  if (!registration.plmnId.mcc || !registration.plmnId.mnc) {
    return res.status(400).json(createInvalidParameterError('plmnId must contain mcc and mnc'));
  }

  try {
    const collection = await getCollection('smsfNon3GppRegistrations');
    const existingReg = await collection.findOne({ ueId });

    const registrationData = {
      ...registration,
      ueId
    };

    if (!existingReg) {
      await collection.insertOne(registrationData);
      const location = `${req.protocol}://${req.get('host')}/nudm-uecm/v1/${ueId}/registrations/smsf-non-3gpp-access`;
      return res.status(201)
        .header('Location', location)
        .json(registrationData);
    } else {
      await collection.replaceOne({ ueId }, registrationData);
      return res.status(200).json(registrationData);
    }
  } catch (error) {
    logger.error('Error creating/updating SMSF non-3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while creating/updating SMSF non-3GPP registration'
    });
  }
});

router.delete('/:ueId/registrations/smsf-non-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const smsfSetId = req.query['smsf-set-id'] as string | undefined;

  try {
    const collection = await getCollection('smsfNon3GppRegistrations');
    const existingReg = await collection.findOne({ ueId }) as SmsfRegistration | null;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'SMSF non-3GPP registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    if (smsfSetId && existingReg.smsfSetId !== smsfSetId) {
      return res.status(422).json({
        type: 'urn:3gpp:error:application',
        title: 'Unprocessable Request',
        status: 422,
        detail: 'SMSF Set ID does not match the registered SMSF Set ID'
      });
    }

    await collection.deleteOne({ ueId });

    return res.status(204).send();
  } catch (error) {
    logger.error('Error deleting SMSF non-3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while deleting SMSF non-3GPP registration'
    });
  }
});

router.get('/:ueId/registrations/smsf-non-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['msisdn', 'extid'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const supportedFeatures = req.query['supported-features'] as string | undefined;

  try {
    const collection = await getCollection('smsfNon3GppRegistrations');
    const registration = await collection.findOne({ ueId }) as SmsfRegistration | null;

    if (!registration) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'SMSF non-3GPP registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    return res.status(200).json(registration);
  } catch (error) {
    logger.error('Error retrieving SMSF non-3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while retrieving SMSF non-3GPP registration'
    });
  }
});

router.patch('/:ueId/registrations/smsf-non-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const modification = req.body as SmsfRegistrationModification;

  if (!modification.smsfInstanceId) {
    return res.status(400).json(createMissingParameterError('Missing required field: smsfInstanceId'));
  }

  const supportedFeatures = req.query['supported-features'] as string | undefined;

  try {
    const collection = await getCollection('smsfNon3GppRegistrations');
    const existingReg = await collection.findOne({ ueId }) as SmsfRegistration | null;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'SMSF non-3GPP registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    const updatedReg = deepMerge(existingReg, modification);

    await collection.replaceOne({ ueId }, updatedReg);

    return res.status(204).send();
  } catch (error) {
    logger.error('Error updating SMSF non-3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while updating SMSF non-3GPP registration'
    });
  }
});

router.put('/:ueId/registrations/ip-sm-gw', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const registration = req.body as IpSmGwRegistration;

  if (!registration || typeof registration !== 'object') {
    return res.status(400).json(createInvalidParameterError('Invalid request body'));
  }

  try {
    const collection = await getCollection('ipSmGwRegistrations');
    const existingReg = await collection.findOne({ ueId });

    const registrationData = {
      ...registration,
      ueId
    };

    if (!existingReg) {
      await collection.insertOne(registrationData);
      const location = `${req.protocol}://${req.get('host')}/nudm-uecm/v1/${ueId}/registrations/ip-sm-gw`;
      return res.status(201)
        .header('Location', location)
        .json(registrationData);
    } else {
      await collection.replaceOne({ ueId }, registrationData);
      return res.status(200).json(registrationData);
    }
  } catch (error) {
    logger.error('Error creating/updating IP-SM-GW registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while creating/updating IP-SM-GW registration'
    });
  }
});

router.delete('/:ueId/registrations/ip-sm-gw', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  try {
    const collection = await getCollection('ipSmGwRegistrations');
    const existingReg = await collection.findOne({ ueId });

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'IP-SM-GW registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    await collection.deleteOne({ ueId });

    return res.status(204).send();
  } catch (error) {
    logger.error('Error deleting IP-SM-GW registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while deleting IP-SM-GW registration'
    });
  }
});

router.get('/:ueId/registrations/ip-sm-gw', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  try {
    const collection = await getCollection('ipSmGwRegistrations');
    const registration = await collection.findOne({ ueId }) as IpSmGwRegistration | null;

    if (!registration) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'IP-SM-GW registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    return res.status(200).json(registration);
  } catch (error) {
    logger.error('Error retrieving IP-SM-GW registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while retrieving IP-SM-GW registration'
    });
  }
});

router.post('/restore-pcscf', async (req: Request, res: Response) => {
  const triggerRequest = req.body as TriggerRequest;

  if (!triggerRequest || typeof triggerRequest !== 'object') {
    return res.status(400).json(createInvalidParameterError('Invalid request body'));
  }

  if (!triggerRequest.supi) {
    return res.status(400).json(createMissingParameterError('Missing required field: supi'));
  }

  const { supi, failedPcscf } = triggerRequest;

  try {
    const amf3GppCollection = await getCollection('amf3GppRegistrations');
    const amfNon3GppCollection = await getCollection('amfNon3GppRegistrations');
    const smfCollection = await getCollection('smfRegistrations');

    const amf3Gpp = await amf3GppCollection.findOne({ supi }) as Amf3GppAccessRegistration | null;
    const amfNon3Gpp = await amfNon3GppCollection.findOne({ supi }) as AmfNon3GppAccessRegistration | null;
    const smfRegistrations = await smfCollection.find({ supi }).toArray() as unknown as SmfRegistration[];

    const registrationsFound = (amf3Gpp !== null) || (amfNon3Gpp !== null) || (smfRegistrations.length > 0);

    if (!registrationsFound) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'No registration context found for the specified SUPI',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    const notification: PcscfRestorationNotification = {
      supi
    };

    if (failedPcscf) {
      notification.failedPcscf = failedPcscf;
    }

    const notificationPromises: Promise<any>[] = [];

    if (amf3Gpp?.pcscfRestorationCallbackUri) {
      notificationPromises.push(
        fetch(amf3Gpp.pcscfRestorationCallbackUri, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(notification)
        }).catch(error => {
          logger.error('Failed to notify AMF 3GPP', { uri: amf3Gpp.pcscfRestorationCallbackUri, error });
        })
      );
    }

    if (amfNon3Gpp?.pcscfRestorationCallbackUri) {
      notificationPromises.push(
        fetch(amfNon3Gpp.pcscfRestorationCallbackUri, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(notification)
        }).catch(error => {
          logger.error('Failed to notify AMF Non-3GPP', { uri: amfNon3Gpp.pcscfRestorationCallbackUri, error });
        })
      );
    }

    for (const smfReg of smfRegistrations) {
      if (smfReg.pcscfRestorationCallbackUri) {
        notificationPromises.push(
          fetch(smfReg.pcscfRestorationCallbackUri, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(notification)
          }).catch(error => {
            logger.error('Failed to notify SMF', { uri: smfReg.pcscfRestorationCallbackUri, error });
          })
        );
      }
    }

    await Promise.allSettled(notificationPromises);

    return res.status(204).send();
  } catch (error) {
    logger.error('Error triggering P-CSCF restoration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while triggering P-CSCF restoration'
    });
  }
});

router.get('/:ueId/registrations/location', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'msisdn', 'extid'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const supportedFeatures = req.query['supported-features'] as string | undefined;

  try {
    const amf3GppCollection = await getCollection('amf3GppRegistrations');
    const amfNon3GppCollection = await getCollection('amfNon3GppRegistrations');

    const amf3Gpp = await amf3GppCollection.findOne({ ueId }) as Amf3GppAccessRegistration | null;
    const amfNon3Gpp = await amfNon3GppCollection.findOne({ ueId }) as AmfNon3GppAccessRegistration | null;

    if (!amf3Gpp && !amfNon3Gpp) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'No location information found for the specified UE',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    const registrationLocationInfoList: RegistrationLocationInfo[] = [];

    if (amf3Gpp) {
      const locationInfo: RegistrationLocationInfo = {
        amfInstanceId: amf3Gpp.amfInstanceId,
        accessTypeList: ['3GPP_ACCESS' as AccessType]
      };

      if (amf3Gpp.guami) {
        locationInfo.guami = amf3Gpp.guami;
      }

      if (amf3Gpp.guami?.plmnId) {
        locationInfo.plmnId = amf3Gpp.guami.plmnId;
      }

      if (amf3Gpp.vgmlcAddress) {
        locationInfo.vgmlcAddress = amf3Gpp.vgmlcAddress;
      }

      registrationLocationInfoList.push(locationInfo);
    }

    if (amfNon3Gpp) {
      const locationInfo: RegistrationLocationInfo = {
        amfInstanceId: amfNon3Gpp.amfInstanceId,
        accessTypeList: ['NON_3GPP_ACCESS' as AccessType]
      };

      if (amfNon3Gpp.guami) {
        locationInfo.guami = amfNon3Gpp.guami;
      }

      if (amfNon3Gpp.guami?.plmnId) {
        locationInfo.plmnId = amfNon3Gpp.guami.plmnId;
      }

      if (amfNon3Gpp.vgmlcAddress) {
        locationInfo.vgmlcAddress = amfNon3Gpp.vgmlcAddress;
      }

      registrationLocationInfoList.push(locationInfo);
    }

    const locationInfo: LocationInfo = {
      registrationLocationInfo: registrationLocationInfoList
    };

    if (amf3Gpp?.supi) {
      locationInfo.supi = amf3Gpp.supi;
    } else if (amfNon3Gpp?.supi) {
      locationInfo.supi = amfNon3Gpp.supi;
    }

    if (supportedFeatures) {
      locationInfo.supportedFeatures = supportedFeatures;
    }

    return res.status(200).json(locationInfo);
  } catch (error) {
    logger.error('Error retrieving location information', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while retrieving location information'
    });
  }
});

router.get('/:ueId/registrations/nwdaf-registrations', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const analyticsIds = req.query['analytics-ids'] as string | string[] | undefined;
  const supportedFeatures = req.query['supported-features'] as string | undefined;

  try {
    const collection = await getCollection('nwdafRegistrations');

    const query: NwdafRegistrationQuery = { ueId };

    if (analyticsIds) {
      const analyticsArray = Array.isArray(analyticsIds) ? analyticsIds : analyticsIds.split(',');
      query.analyticsIds = { $in: analyticsArray };
    }

    const registrations = await collection.find(query).toArray() as unknown as NwdafRegistration[];

    if (!registrations || registrations.length === 0) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'NWDAF registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    return res.status(200).json(registrations);
  } catch (error) {
    logger.error('Error retrieving NWDAF registrations', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while retrieving NWDAF registrations'
    });
  }
});

router.put('/:ueId/registrations/nwdaf-registrations/:nwdafRegistrationId', async (req: Request, res: Response) => {
  const { ueId, nwdafRegistrationId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const registration = req.body as NwdafRegistration;

  if (!registration.nwdafInstanceId) {
    return res.status(400).json(createMissingParameterError('Missing required field: nwdafInstanceId'));
  }

  if (!registration.analyticsIds || !Array.isArray(registration.analyticsIds) || registration.analyticsIds.length === 0) {
    return res.status(400).json(createMissingParameterError('Missing required field: analyticsIds'));
  }

  try {
    const collection = await getCollection('nwdafRegistrations');
    const existingReg = await collection.findOne({ ueId, nwdafRegistrationId }) as NwdafRegistration | null;

    const registrationData = {
      ...registration,
      ueId,
      nwdafRegistrationId,
      registrationTime: registration.registrationTime || new Date().toISOString()
    };

    if (!existingReg) {
      await collection.insertOne(registrationData);
      const location = `${req.protocol}://${req.get('host')}/nudm-uecm/v1/${ueId}/registrations/nwdaf-registrations/${nwdafRegistrationId}`;
      return res.status(201)
        .header('Location', location)
        .json(registrationData);
    } else {
      await collection.replaceOne({ ueId, nwdafRegistrationId }, registrationData);
      return res.status(200).json(registrationData);
    }
  } catch (error) {
    logger.error('Error creating/updating NWDAF registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while creating/updating NWDAF registration'
    });
  }
});

router.delete('/:ueId/registrations/nwdaf-registrations/:nwdafRegistrationId', async (req: Request, res: Response) => {
  const { ueId, nwdafRegistrationId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  try {
    const collection = await getCollection('nwdafRegistrations');
    const existingReg = await collection.findOne({ ueId, nwdafRegistrationId }) as NwdafRegistration | null;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'NWDAF registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    await collection.deleteOne({ ueId, nwdafRegistrationId });

    return res.status(204).send();
  } catch (error) {
    logger.error('Error deleting NWDAF registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while deleting NWDAF registration'
    });
  }
});

router.patch('/:ueId/registrations/nwdaf-registrations/:nwdafRegistrationId', async (req: Request, res: Response) => {
  const { ueId, nwdafRegistrationId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const modification = req.body as NwdafRegistrationModification;

  if (!modification.nwdafInstanceId) {
    return res.status(400).json(createMissingParameterError('Missing required field: nwdafInstanceId'));
  }

  const supportedFeatures = req.query['supported-features'] as string | undefined;

  try {
    const collection = await getCollection('nwdafRegistrations');
    const existingReg = await collection.findOne({ ueId, nwdafRegistrationId }) as NwdafRegistration | null;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'NWDAF registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    const updatedReg = deepMerge(existingReg, modification);

    await collection.replaceOne({ ueId, nwdafRegistrationId }, updatedReg);

    return res.status(204).send();
  } catch (error) {
    logger.error('Error updating NWDAF registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while updating NWDAF registration'
    });
  }
});

// doesnt exist anywhere??
router.get('/:ueId/registrations/trigger-auth', notImplemented);

export default router;

