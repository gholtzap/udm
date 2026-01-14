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
  Snssai,
  Dnn,
  deepMerge,
  PatchResult,
  AccessType
} from '../types/common-types';
import logger from '../utils/logger';

const router = Router();

const notImplemented = (req: Request, res: Response) => {
  res.status(501).json({
    title: 'Not Implemented',
    status: 501,
    detail: 'This endpoint is not yet implemented'
  });
};

router.get('/:ueId/registrations', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'msisdn', 'extid'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const registrationDatasetNamesParam = req.query['registration-dataset-names'];
  if (!registrationDatasetNamesParam) {
    return res.status(400).json(createMissingParameterError('Missing required query parameter: registration-dataset-names'));
  }

  let registrationDatasetNames: string[];
  if (typeof registrationDatasetNamesParam === 'string') {
    registrationDatasetNames = registrationDatasetNamesParam.split(',');
  } else if (Array.isArray(registrationDatasetNamesParam)) {
    registrationDatasetNames = registrationDatasetNamesParam as string[];
  } else {
    return res.status(400).json(createInvalidParameterError('Invalid registration-dataset-names format'));
  }

  if (registrationDatasetNames.length < 2) {
    return res.status(400).json(createInvalidParameterError('registration-dataset-names must contain at least 2 values'));
  }

  const validDatasetNames = Object.values(RegistrationDataSetName);
  const invalidNames = registrationDatasetNames.filter(name => !validDatasetNames.includes(name as RegistrationDataSetName));
  
  if (invalidNames.length > 0) {
    return res.status(400).json(createInvalidParameterError(`Invalid registration-dataset-names: ${invalidNames.join(', ')}`));
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
    const registrationDataSets: RegistrationDataSets = {};

    for (const datasetName of registrationDatasetNames) {
      switch (datasetName) {
        case RegistrationDataSetName.AMF_3GPP:
          {
            const collection = await getCollection('amf3GppRegistrations');
            const registration = await collection.findOne({ ueId }) as Amf3GppAccessRegistration | null;
            if (registration) {
              registrationDataSets.amf3Gpp = registration;
            }
          }
          break;

        case RegistrationDataSetName.AMF_NON_3GPP:
          {
            const collection = await getCollection('amfNon3GppRegistrations');
            const registration = await collection.findOne({ ueId }) as AmfNon3GppAccessRegistration | null;
            if (registration) {
              registrationDataSets.amfNon3Gpp = registration;
            }
          }
          break;

        case RegistrationDataSetName.SMF_PDU_SESSIONS:
          {
            const collection = await getCollection('smfRegistrations');
            let query: any = { ueId };

            if (singleNssai) {
              query['singleNssai.sst'] = singleNssai.sst;
              if (singleNssai.sd !== undefined) {
                query['singleNssai.sd'] = singleNssai.sd;
              }
            }

            if (dnn) {
              query.dnn = dnn;
            }

            const registrations = await collection.find(query).toArray();
            if (registrations.length > 0) {
              registrationDataSets.smfRegistration = {
                smfRegistrationList: registrations as any[]
              };
            }
          }
          break;

        case RegistrationDataSetName.SMSF_3GPP:
          {
            const collection = await getCollection('smsf3GppRegistrations');
            const registration = await collection.findOne({ ueId }) as SmsfRegistration | null;
            if (registration) {
              registrationDataSets.smsf3Gpp = registration;
            }
          }
          break;

        case RegistrationDataSetName.SMSF_NON_3GPP:
          {
            const collection = await getCollection('smsfNon3GppRegistrations');
            const registration = await collection.findOne({ ueId }) as SmsfRegistration | null;
            if (registration) {
              registrationDataSets.smsfNon3Gpp = registration;
            }
          }
          break;

        case RegistrationDataSetName.IP_SM_GW:
          {
            const collection = await getCollection('ipSmGwRegistrations');
            const registration = await collection.findOne({ ueId }) as IpSmGwRegistration | null;
            if (registration) {
              registrationDataSets.ipSmGw = registration;
            }
          }
          break;

        case RegistrationDataSetName.NWDAF:
          {
            const collection = await getCollection('nwdafRegistrations');
            const registrations = await collection.find({ ueId }).toArray();
            if (registrations.length > 0) {
              registrationDataSets.nwdafRegistration = {
                nwdafRegistrationList: registrations as any[]
              };
            }
          }
          break;
      }
    }

    const hasAnyData = Object.keys(registrationDataSets).length > 0;
    if (!hasAnyData) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'No registration data found for the specified UE',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    return res.status(200).json(registrationDataSets);
  } catch (error) {
    logger.error('Error retrieving registration data', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while retrieving registration data'
    });
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
    const smsf3GppCollection = await getCollection('smsf3GppRegistrations');
    const smsfNon3GppCollection = await getCollection('smsfNon3GppRegistrations');
    const ipSmGwCollection = await getCollection('ipSmGwRegistrations');

    const smsf3Gpp = await smsf3GppCollection.findOne({ ueId }) as SmsfRegistration | null;
    const smsfNon3Gpp = await smsfNon3GppCollection.findOne({ ueId }) as SmsfRegistration | null;
    const ipSmGwReg = await ipSmGwCollection.findOne({ ueId }) as IpSmGwRegistration | null;

    if (!smsf3Gpp && !smsfNon3Gpp && !ipSmGwReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'No SMS routing information found for the specified UE',
        cause: 'USER_NOT_FOUND'
      });
    }

    const response: RoutingInfoSmResponse = {};

    if (smsf3Gpp) {
      response.smsf3Gpp = smsf3Gpp;
    }

    if (smsfNon3Gpp) {
      response.smsfNon3Gpp = smsfNon3Gpp;
    }

    if (ipSmGwReg && requestBody.ipSmGwInd !== false) {
      const ipSmGwInfo: IpSmGwInfo = {
        ipSmGwRegistration: ipSmGwReg
      };
      response.ipSmGw = ipSmGwInfo;
    }

    return res.status(200).json(response);
  } catch (error) {
    logger.error('Error retrieving SMS routing information', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while retrieving SMS routing information'
    });
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

  if (!registration.ratType) {
    return res.status(400).json(createMissingParameterError('Missing required field: ratType'));
  }

  try {
    const collection = await getCollection('amf3GppRegistrations');
    const existingReg = await collection.findOne({ ueId });

    const registrationData = {
      ...registration,
      ueId
    };

    if (!existingReg) {
      await collection.insertOne(registrationData);
      const location = `${req.protocol}://${req.get('host')}/nudm-uecm/v1/${ueId}/registrations/amf-3gpp-access`;
      return res.status(201)
        .header('Location', location)
        .json(registrationData);
    } else {
      await collection.replaceOne({ ueId }, registrationData);
      return res.status(200).json(registrationData);
    }
  } catch (error) {
    logger.error('Error creating/updating AMF 3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while creating/updating AMF 3GPP registration'
    });
  }
});

router.patch('/:ueId/registrations/amf-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const modification = req.body as Amf3GppAccessRegistrationModification;

  if (!modification.guami) {
    return res.status(400).json(createMissingParameterError('Missing required field: guami'));
  }

  const supportedFeatures = req.query['supported-features'] as string | undefined;

  try {
    const collection = await getCollection('amf3GppRegistrations');
    const existingReg = await collection.findOne({ ueId }) as Amf3GppAccessRegistration | null;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'AMF 3GPP registration context not found',
        cause: 'CONTEXT_NOT_FOUND'
      });
    }

    const updatedReg = deepMerge(existingReg, modification);

    await collection.replaceOne({ ueId }, updatedReg);

    return res.status(204).send();
  } catch (error) {
    logger.error('Error updating AMF 3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while updating AMF 3GPP registration'
    });
  }
});

router.get('/:ueId/registrations/amf-3gpp-access', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'msisdn', 'extid'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const supportedFeatures = req.query['supported-features'] as string | undefined;

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

    return res.status(200).json(registration);
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

  if (!deregInfo.deregReason) {
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

    await collection.deleteOne({ ueId });

    return res.status(204).send();
  } catch (error) {
    logger.error('Error deregistering AMF 3GPP access', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while deregistering AMF 3GPP access'
    });
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

  if (!peiUpdateInfo.pei) {
    return res.status(400).json(createMissingParameterError('Missing required field: pei'));
  }

  try {
    const collection = await getCollection('amf3GppRegistrations');
    const existingReg = await collection.findOne({ ueId }) as Amf3GppAccessRegistration | null;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'AMF 3GPP registration context not found',
        cause: 'USER_NOT_FOUND'
      });
    }

    await collection.updateOne(
      { ueId },
      { $set: { pei: peiUpdateInfo.pei } }
    );

    return res.status(204).send();
  } catch (error) {
    logger.error('Error updating PEI in AMF 3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while updating PEI'
    });
  }
});

router.post('/:ueId/registrations/amf-3gpp-access/roaming-info-update', async (req: Request, res: Response) => {
  const { ueId } = req.params;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'gli', 'gci'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const roamingInfoUpdate = req.body as RoamingInfoUpdate;

  if (!roamingInfoUpdate || typeof roamingInfoUpdate !== 'object') {
    return res.status(400).json(createInvalidParameterError('Invalid request body'));
  }

  if (!roamingInfoUpdate.servingPlmn) {
    return res.status(400).json(createMissingParameterError('Missing required field: servingPlmn'));
  }

  if (!roamingInfoUpdate.servingPlmn.mcc || !roamingInfoUpdate.servingPlmn.mnc) {
    return res.status(400).json(createInvalidParameterError('servingPlmn must contain mcc and mnc'));
  }

  try {
    const collection = await getCollection('amf3GppRegistrations');
    const existingReg = await collection.findOne({ ueId }) as any;

    if (!existingReg) {
      return res.status(404).json({
        type: 'urn:3gpp:error:application',
        title: 'Not Found',
        status: 404,
        detail: 'AMF 3GPP registration context not found',
        cause: 'USER_NOT_FOUND'
      });
    }

    const hasExistingRoamingInfo = existingReg.servingPlmn !== undefined;

    const updateFields: any = {
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
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while updating roaming information'
    });
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

  if (!registration.ratType) {
    return res.status(400).json(createMissingParameterError('Missing required field: ratType'));
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

    if (!existingReg) {
      await collection.insertOne(registrationData);
      const location = `${req.protocol}://${req.get('host')}/nudm-uecm/v1/${ueId}/registrations/amf-non-3gpp-access`;
      return res.status(201)
        .header('Location', location)
        .json(registrationData);
    } else {
      await collection.replaceOne({ ueId }, registrationData);
      return res.status(200).json(registrationData);
    }
  } catch (error) {
    logger.error('Error creating/updating AMF non-3GPP registration', { error });
    return res.status(500).json({
      type: 'urn:3gpp:error:system',
      title: 'Internal Server Error',
      status: 500,
      detail: 'An error occurred while creating/updating AMF non-3GPP registration'
    });
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
    let query: any = { ueId };

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
    
    let query: any = { ueId };
    
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

