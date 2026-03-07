import { Router, Request, Response } from 'express';
import { PpData, FiveGVnGroupConfiguration, MulticastMbsGroupMemb, PpDataEntry } from '../types/nudm-pp-types';
import { validateUeIdentity, createInvalidParameterError, createNotFoundError, extGroupIdPattern, deepMerge, createNotImplementedError } from '../types/common-types';

const router = Router();

const ppDataStore = new Map<string, PpData>();
const vnGroupStore = new Map<string, FiveGVnGroupConfiguration>();
const mbsGroupStore = new Map<string, MulticastMbsGroupMemb>();

const notImplemented = (req: Request, res: Response) => {
  res.status(501).json(createNotImplementedError('This endpoint is not yet implemented'));
};

router.get('/:ueId/pp-data', (req: Request, res: Response) => {
  const { ueId } = req.params;
  const afInstanceId = req.query['af-instance-id'];
  const mtcProviderInformation = req.query['mtc-provider-information'];
  const supportedFeatures = req.query['supported-features'];

  if (!validateUeIdentity(ueId, ['msisdn', 'extid', 'imsi', 'nai', 'gci', 'gli', 'extgroupid'])) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  let ppData = ppDataStore.get(ueId);
  
  if (!ppData) {
    ppData = {
      communicationCharacteristics: {
        ppSubsRegTimer: {
          subsRegTimer: 3600,
          afInstanceId: afInstanceId as string || 'af-default',
          referenceId: 1
        },
        ppActiveTime: {
          activeTime: 300,
          afInstanceId: afInstanceId as string || 'af-default',
          referenceId: 2
        },
        ppDlPacketCount: 10
      },
      expectedUeBehaviourParameters: {
        afInstanceId: afInstanceId as string || 'af-default',
        referenceId: 3,
        stationaryIndication: 'STATIONARY',
        communicationDurationTime: 600,
        periodicTime: 3600
      },
      ecRestriction: {
        afInstanceId: afInstanceId as string || 'af-default',
        referenceId: 4,
        plmnEcInfos: [
          {
            plmnId: {
              mcc: '001',
              mnc: '01'
            },
            ecRestrictionDataNb: false
          }
        ]
      }
    };
    ppDataStore.set(ueId, ppData);
  }

  const response: PpData = { ...ppData };

  if (supportedFeatures) {
    response.supportedFeatures = supportedFeatures as string;
  }

  return res.status(200).json(response);
});

router.patch('/:ueId/pp-data', (req: Request, res: Response) => {
  const { ueId } = req.params;
  const afInstanceId = req.query['af-instance-id'];
  const mtcProviderInformation = req.query['mtc-provider-information'];
  const body = req.body;

  if (!validateUeIdentity(ueId, ['msisdn', 'extid', 'imsi', 'nai', 'gci', 'gli', 'extgroupid'])) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  let ppData = ppDataStore.get(ueId);
  
  if (!ppData) {
    ppData = {
      communicationCharacteristics: {
        ppSubsRegTimer: {
          subsRegTimer: 3600,
          afInstanceId: afInstanceId as string || 'af-default',
          referenceId: 1
        },
        ppActiveTime: {
          activeTime: 300,
          afInstanceId: afInstanceId as string || 'af-default',
          referenceId: 2
        },
        ppDlPacketCount: 10
      },
      expectedUeBehaviourParameters: {
        afInstanceId: afInstanceId as string || 'af-default',
        referenceId: 3,
        stationaryIndication: 'STATIONARY',
        communicationDurationTime: 600,
        periodicTime: 3600
      },
      ecRestriction: {
        afInstanceId: afInstanceId as string || 'af-default',
        referenceId: 4,
        plmnEcInfos: [
          {
            plmnId: {
              mcc: '001',
              mnc: '01'
            },
            ecRestrictionDataNb: false
          }
        ]
      }
    };
  }

  ppData = deepMerge(ppData!, body) as PpData;
  ppDataStore.set(ueId, ppData);

  return res.status(204).send();
});

router.put('/5g-vn-groups/:extGroupId', (req: Request, res: Response) => {
  const { extGroupId } = req.params;
  const body = req.body;

  if (!extGroupIdPattern.test(extGroupId)) {
    return res.status(400).json(createInvalidParameterError('Invalid extGroupId format'));
  }

  if (body === undefined || body === null || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  vnGroupStore.set(extGroupId, body);

  return res.status(201).send();
});

router.delete('/5g-vn-groups/:extGroupId', (req: Request, res: Response) => {
  const { extGroupId } = req.params;
  const mtcProviderInfo = req.query['mtc-provider-info'];
  const afId = req.query['af-id'];

  if (!extGroupIdPattern.test(extGroupId)) {
    return res.status(400).json(createInvalidParameterError('Invalid extGroupId format'));
  }

  if (!vnGroupStore.has(extGroupId)) {
    return res.status(404).json(createNotFoundError('5G VN Group not found'));
  }

  vnGroupStore.delete(extGroupId);

  return res.status(204).send();
});

router.patch('/5g-vn-groups/:extGroupId', (req: Request, res: Response) => {
  const { extGroupId } = req.params;
  const body = req.body;

  if (!extGroupIdPattern.test(extGroupId)) {
    return res.status(400).json(createInvalidParameterError('Invalid extGroupId format'));
  }

  if (!vnGroupStore.has(extGroupId)) {
    return res.status(404).json(createNotFoundError('5G VN Group not found'));
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  let vnGroupConfig = vnGroupStore.get(extGroupId);

  vnGroupConfig = deepMerge(vnGroupConfig!, body) as FiveGVnGroupConfiguration;
  vnGroupStore.set(extGroupId, vnGroupConfig);

  return res.status(204).send();
});

router.get('/5g-vn-groups/:extGroupId', (req: Request, res: Response) => {
  const { extGroupId } = req.params;

  if (!extGroupIdPattern.test(extGroupId)) {
    return res.status(400).json(createInvalidParameterError('Invalid extGroupId format'));
  }

  if (!vnGroupStore.has(extGroupId)) {
    return res.status(404).json(createNotFoundError('5G VN Group not found'));
  }

  const vnGroupConfig = vnGroupStore.get(extGroupId);

  return res.status(200).json(vnGroupConfig);
});

router.put('/:ueId/pp-data-store/:afInstanceId', (req: Request, res: Response) => {
  const { ueId, afInstanceId } = req.params;
  const body = req.body;

  if (!validateUeIdentity(ueId, ['msisdn', 'extid', 'imsi', 'nai', 'gci', 'gli', 'extgroupid', 'anyUE'])) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  if (!afInstanceId || typeof afInstanceId !== 'string' || afInstanceId.trim() === '') {
    return res.status(400).json(createInvalidParameterError('Invalid afInstanceId'));
  }

  if (body === undefined || body === null || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  const storeKey = `${ueId}:${afInstanceId}`;
  const existingEntry = ppDataStore.get(storeKey);

  ppDataStore.set(storeKey, body);

  if (existingEntry) {
    return res.status(204).send();
  } else {
    return res.status(201).json(body);
  }
});

router.delete('/:ueId/pp-data-store/:afInstanceId', (req: Request, res: Response) => {
  const { ueId, afInstanceId } = req.params;
  const mtcProviderInformation = req.query['mtc-provider-information'];

  if (!validateUeIdentity(ueId, ['msisdn', 'extid', 'imsi', 'nai', 'gci', 'gli', 'extgroupid', 'anyUE'])) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  if (!afInstanceId || typeof afInstanceId !== 'string' || afInstanceId.trim() === '') {
    return res.status(400).json(createInvalidParameterError('Invalid afInstanceId'));
  }

  const storeKey = `${ueId}:${afInstanceId}`;
  
  if (!ppDataStore.has(storeKey)) {
    return res.status(404).json(createNotFoundError('PP Data Entry not found'));
  }

  ppDataStore.delete(storeKey);

  return res.status(204).send();
});

router.get('/:ueId/pp-data-store/:afInstanceId', (req: Request, res: Response) => {
  const { ueId, afInstanceId } = req.params;
  const mtcProviderInformation = req.query['mtc-provider-information'];
  const supportedFeatures = req.query['supported-features'];

  if (!validateUeIdentity(ueId, ['msisdn', 'extid', 'imsi', 'nai', 'gci', 'gli', 'extgroupid', 'anyUE'])) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  if (!afInstanceId || typeof afInstanceId !== 'string' || afInstanceId.trim() === '') {
    return res.status(400).json(createInvalidParameterError('Invalid afInstanceId'));
  }

  const storeKey = `${ueId}:${afInstanceId}`;
  
  if (!ppDataStore.has(storeKey)) {
    return res.status(404).json(createNotFoundError('PP Data Entry not found'));
  }

  const ppDataEntry = ppDataStore.get(storeKey);
  const response: PpDataEntry = { ...ppDataEntry } as PpDataEntry;

  if (supportedFeatures) {
    response.supportedFeatures = supportedFeatures as string;
  }

  return res.status(200).json(response);
});

router.put('/mbs-group-membership/:extGroupId', (req: Request, res: Response) => {
  const { extGroupId } = req.params;
  const body = req.body;

  if (!extGroupIdPattern.test(extGroupId)) {
    return res.status(400).json(createInvalidParameterError('Invalid extGroupId format'));
  }

  if (body === undefined || body === null || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  if (!body.multicastGroupMemb || !Array.isArray(body.multicastGroupMemb) || body.multicastGroupMemb.length === 0) {
    return res.status(400).json(createInvalidParameterError('multicastGroupMemb is required and must be a non-empty array'));
  }

  mbsGroupStore.set(extGroupId, body);

  return res.status(201).send();
});

router.delete('/mbs-group-membership/:extGroupId', (req: Request, res: Response) => {
  const { extGroupId } = req.params;

  if (!extGroupIdPattern.test(extGroupId)) {
    return res.status(400).json(createInvalidParameterError('Invalid extGroupId format'));
  }

  if (!mbsGroupStore.has(extGroupId)) {
    return res.status(404).json(createNotFoundError('5G MBS Group not found'));
  }

  mbsGroupStore.delete(extGroupId);

  return res.status(204).send();
});

router.patch('/mbs-group-membership/:extGroupId', (req: Request, res: Response) => {
  const { extGroupId } = req.params;
  const body = req.body;

  if (!extGroupIdPattern.test(extGroupId)) {
    return res.status(400).json(createInvalidParameterError('Invalid extGroupId format'));
  }

  if (!mbsGroupStore.has(extGroupId)) {
    return res.status(404).json(createNotFoundError('5G MBS Group not found'));
  }

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  let mbsGroupConfig = mbsGroupStore.get(extGroupId);

  mbsGroupConfig = deepMerge(mbsGroupConfig!, body) as MulticastMbsGroupMemb;
  mbsGroupStore.set(extGroupId, mbsGroupConfig);

  return res.status(204).send();
});

router.get('/mbs-group-membership/:extGroupId', (req: Request, res: Response) => {
  const { extGroupId } = req.params;

  if (!extGroupIdPattern.test(extGroupId)) {
    return res.status(400).json(createInvalidParameterError('Invalid extGroupId format'));
  }

  if (!mbsGroupStore.has(extGroupId)) {
    return res.status(404).json(createNotFoundError('5G MBS Group not found'));
  }

  const mbsGroupConfig = mbsGroupStore.get(extGroupId);

  return res.status(200).json(mbsGroupConfig);
});

export default router;

