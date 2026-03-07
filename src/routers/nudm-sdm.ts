import { Router, Request, Response } from 'express';
import { 
  SubscriptionDataSets, 
  DataSetName, 
  AccessAndMobilitySubscriptionData,
  SmfSelectionSubscriptionData,
  SessionManagementSubscriptionData,
  SmsSubscriptionData,
  SmsManagementSubscriptionData,
  UeContextInAmfData,
  UeContextInSmfData,
  UeContextInSmsfData,
  TraceData,
  TraceDataResponse,
  TraceDepth,
  LcsPrivacyData,
  LcsMoData,
  LcsMoServiceClass,
  LcsSubscriptionData,
  PruInd,
  V2xSubscriptionData,
  LcsBroadcastAssistanceTypesData,
  ProseSubscriptionData,
  MbsSubscriptionData,
  UcSubscriptionData,
  UcPurpose,
  UserConsent,
  Nssai,
  EnhancedCoverageRestrictionData,
  SmSubsData,
  PduSessionTypes,
  SscModes,
  SscMode,
  SubscribedDefaultQos,
  PreemptionCapability,
  PreemptionVulnerability,
  LocationPrivacyInd,
  LcsClientClass,
  PrivacyCheckRelatedAction,
  SdmSubscription,
  SdmSubsModification,
  IdTranslationResult,
  GpsiType,
  AppPortId,
  AcknowledgeInfo,
  SorUpdateInfo,
  SorInfo,
  SharedData,
  SharedDataId,
  GroupIdentifiers,
  ExtGroupId,
  UeId,
  UeIdentifiers,
  SupiInfo,
  TimeSyncSubscriptionData,
  RangingSlPosSubscriptionData,
  A2xSubscriptionData,
  RangingSlPrivacyData,
  RangingSlPrivacyInd,
  RangingSlPrivacyCheckRelatedAction
} from '../types/nudm-sdm-types';
import { validateUeIdentity, createInvalidParameterError, createMissingParameterError, createNotFoundError, PlmnId, Snssai, AccessType, PduSessionType, createNotImplementedError, createForbiddenError } from '../types/common-types';
import {
  getSubscriptionData,
  setSubscriptionData,
  getAllSubscriptionData,
  getSdmSubscription,
  setSdmSubscription,
  deleteSdmSubscription,
  hasSdmSubscription,
  deleteSdmSubscriptionsForUe,
  getSharedData,
  setSharedData,
  getSharedDataSubscription,
  setSharedDataSubscription,
  deleteSharedDataSubscription,
  hasSharedDataSubscription,
  getGroupIdentifiers,
  setGroupIdentifiers
} from '../db/sdm-db';

const router = Router();

const notImplemented = (req: Request, res: Response) => {
  res.status(501).json(createNotImplementedError('This endpoint is not yet implemented'));
};

router.get('/:supi', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const datasetNames = req.query['dataset-names'] as string;
  const plmnId = req.query['plmn-id'] as string | undefined;
  const adjacentPlmns = req.query['adjacent-plmns'] as string | undefined;
  const singleNssai = req.query['single-nssai'] as string | undefined;
  const dnn = req.query['dnn'] as string | undefined;
  const ucPurpose = req.query['uc-purpose'] as string | undefined;
  const disasterRoamingInd = req.query['disaster-roaming-ind'] === 'true';
  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  if (!datasetNames) {
    return res.status(400).json(createMissingParameterError('dataset-names query parameter is required'));
  }

  const requestedDatasets = datasetNames.split(',').map(ds => ds.trim() as DataSetName);

  for (const dataset of requestedDatasets) {
    if (!Object.values(DataSetName).includes(dataset)) {
      return res.status(400).json(createInvalidParameterError(`Invalid dataset name: ${dataset}`));
    }
  }

  let storedData = await getSubscriptionData(supi);

  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: SubscriptionDataSets = {};

  for (const dataset of requestedDatasets) {
    switch (dataset) {
      case DataSetName.AM:
        response.amData = storedData.amData;
        break;
      case DataSetName.SMF_SEL:
        response.smfSelData = storedData.smfSelData;
        break;
      case DataSetName.UEC_SMF:
        response.uecSmfData = storedData.uecSmfData;
        break;
      case DataSetName.UEC_SMSF:
        response.uecSmsfData = storedData.uecSmsfData;
        break;
      case DataSetName.SMS_SUB:
        response.smsSubsData = storedData.smsSubsData;
        break;
      case DataSetName.SM:
        response.smData = storedData.smData;
        break;
      case DataSetName.TRACE:
        response.traceData = storedData.traceData;
        break;
      case DataSetName.SMS_MNG:
        response.smsMngData = storedData.smsMngData;
        break;
      case DataSetName.LCS_PRIVACY:
        response.lcsPrivacyData = storedData.lcsPrivacyData;
        break;
      case DataSetName.LCS_MO:
        response.lcsMoData = storedData.lcsMoData;
        break;
      case DataSetName.UEC_AMF:
        response.uecAmfData = storedData.uecAmfData;
        break;
      case DataSetName.V2X:
        response.v2xData = storedData.v2xData;
        break;
      case DataSetName.LCS_BCA:
        response.lcsBroadcastAssistanceTypesData = storedData.lcsBroadcastAssistanceTypesData;
        break;
      case DataSetName.PROSE:
        response.proseData = storedData.proseData;
        break;
      case DataSetName.UC:
        response.ucData = storedData.ucData;
        break;
      case DataSetName.MBS:
        response.mbsData = storedData.mbsData;
        break;
    }
  }

  return res.status(200).json(response);
});

router.get('/:supi/nssai', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const supportedFeatures = req.query['supported-features'] as string | undefined;
  const plmnId = req.query['plmn-id'] as string | undefined;
  const disasterRoamingInd = req.query['disaster-roaming-ind'] === 'true';

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);

  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.amData?.nssai) {
    return res.status(404).json(createNotFoundError(`NSSAI data not found for SUPI: ${supi}`));
  }

  const response: Nssai = {
    ...storedData.amData.nssai
  };

  if (supportedFeatures) {
    response.supportedFeatures = supportedFeatures;
  }

  return res.status(200).json(response);
});

router.get('/:supi/ue-context-in-amf-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);

  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.uecAmfData) {
    storedData.uecAmfData = {
      amfInfo: [
        {
          amfInstanceId: `amf-instance-${supi.slice(-8)}`,
          guami: {
            plmnId: {
              mcc: '001',
              mnc: '01'
            },
            amfId: '010001'
          },
          accessType: AccessType.THREE_GPP_ACCESS
        }
      ]
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: UeContextInAmfData = {
    ...storedData.uecAmfData
  };

  return res.status(200).json(response);
});

router.get('/:supi/am-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const supportedFeatures = req.query['supported-features'] as string | undefined;
  const plmnIdParam = req.query['plmn-id'] as string | undefined;
  const adjacentPlmnsParam = req.query['adjacent-plmns'] as string | undefined;
  const disasterRoamingInd = req.query['disaster-roaming-ind'] === 'true';
  const sharedDataIds = req.query['shared-data-ids'] as string | undefined;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let plmnId: PlmnId | undefined;
  if (plmnIdParam) {
    try {
      plmnId = JSON.parse(plmnIdParam) as PlmnId;
      if (!plmnId.mcc || !plmnId.mnc) {
        return res.status(400).json(createInvalidParameterError('Invalid plmn-id format'));
      }
    } catch (e) {
      return res.status(400).json(createInvalidParameterError('Invalid plmn-id JSON format'));
    }
  }

  let adjacentPlmns: PlmnId[] | undefined;
  if (adjacentPlmnsParam) {
    try {
      adjacentPlmns = JSON.parse(adjacentPlmnsParam) as PlmnId[];
      if (!Array.isArray(adjacentPlmns) || adjacentPlmns.length === 0) {
        return res.status(400).json(createInvalidParameterError('Invalid adjacent-plmns format'));
      }
    } catch (e) {
      return res.status(400).json(createInvalidParameterError('Invalid adjacent-plmns JSON format'));
    }
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.amData) {
    return res.status(404).json(createNotFoundError(`Access and Mobility Subscription Data not found for SUPI: ${supi}`));
  }

  const response: AccessAndMobilitySubscriptionData = {
    ...storedData.amData
  };

  if (supportedFeatures) {
    response.supportedFeatures = supportedFeatures;
  }

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-amdata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/am-data/ecr-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: EnhancedCoverageRestrictionData = {
    plmnEcInfoList: []
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-ecrdata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/smf-select-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const supportedFeatures = req.query['supported-features'] as string | undefined;
  const plmnIdParam = req.query['plmn-id'] as string | undefined;
  const disasterRoamingInd = req.query['disaster-roaming-ind'] === 'true';
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let plmnId: PlmnId | undefined;
  if (plmnIdParam) {
    try {
      plmnId = JSON.parse(plmnIdParam) as PlmnId;
      if (!plmnId.mcc || !plmnId.mnc) {
        return res.status(400).json(createInvalidParameterError('Invalid plmn-id format'));
      }
    } catch (e) {
      return res.status(400).json(createInvalidParameterError('Invalid plmn-id JSON format'));
    }
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.smfSelData) {
    return res.status(404).json(createNotFoundError(`SMF Selection Subscription Data not found for SUPI: ${supi}`));
  }

  const response: SmfSelectionSubscriptionData = {
    ...storedData.smfSelData
  };

  if (supportedFeatures) {
    response.supportedFeatures = supportedFeatures;
  }

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-smfseldata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/ue-context-in-smf-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const plmnIdParam = req.query['plmn-id'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let plmnId: PlmnId | undefined;
  if (plmnIdParam) {
    try {
      plmnId = JSON.parse(plmnIdParam) as PlmnId;
      if (!plmnId.mcc || !plmnId.mnc) {
        return res.status(400).json(createInvalidParameterError('Invalid plmn-id format'));
      }
    } catch (e) {
      return res.status(400).json(createInvalidParameterError('Invalid plmn-id JSON format'));
    }
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.uecSmfData) {
    const contextPlmnId: PlmnId = plmnId || { mcc: '001', mnc: '01' };
    
    storedData.uecSmfData = {
      pduSessions: {
        '1': {
          dnn: 'internet',
          smfInstanceId: `smf-instance-${supi.slice(-8)}`,
          plmnId: contextPlmnId,
          singleNssai: {
            sst: 1,
            sd: '000001'
          }
        }
      },
      pgwInfo: [
        {
          dnn: 'internet',
          pgwFqdn: `pgw.${contextPlmnId.mcc}.${contextPlmnId.mnc}.5gc.mnc${contextPlmnId.mnc}.mcc${contextPlmnId.mcc}.3gppnetwork.org`,
          plmnId: contextPlmnId
        }
      ]
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: UeContextInSmfData = {
    ...storedData.uecSmfData
  };

  return res.status(200).json(response);
});

router.get('/:supi/ue-context-in-smsf-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.uecSmsfData) {
    storedData.uecSmsfData = {
      smsfInfo3GppAccess: {
        smsfInstanceId: `smsf-3gpp-instance-${supi.slice(-8)}`,
        plmnId: {
          mcc: '001',
          mnc: '01'
        },
        smsfSetId: `smsf-set-${supi.slice(-6)}`
      },
      smsfInfoNon3GppAccess: {
        smsfInstanceId: `smsf-non3gpp-instance-${supi.slice(-8)}`,
        plmnId: {
          mcc: '001',
          mnc: '01'
        }
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: UeContextInSmsfData = {
    ...storedData.uecSmsfData
  };

  return res.status(200).json(response);
});

router.get('/:supi/trace-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const plmnIdParam = req.query['plmn-id'] as string | undefined;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let plmnId: PlmnId | undefined;
  if (plmnIdParam) {
    try {
      plmnId = JSON.parse(plmnIdParam) as PlmnId;
      if (!plmnId.mcc || !plmnId.mnc) {
        return res.status(400).json(createInvalidParameterError('Invalid plmn-id format'));
      }
    } catch (e) {
      return res.status(400).json(createInvalidParameterError('Invalid plmn-id JSON format'));
    }
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.traceData) {
    const contextPlmnId: PlmnId = plmnId || { mcc: '001', mnc: '01' };
    
    storedData.traceData = {
      traceRef: `${contextPlmnId.mcc}${contextPlmnId.mnc}-trace-${supi.slice(-8)}`,
      traceDepth: TraceDepth.MEDIUM,
      neTypeList: 'AMF,SMF,UPF',
      eventList: 'N1N2_MESSAGE_TRANSFER,PDU_SESSION_ESTABLISHMENT,PDU_SESSION_RELEASE',
      collectionEntityIpv4Addr: '192.168.100.10',
      interfaceList: 'N1,N2,N4'
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: TraceDataResponse = {
    traceData: storedData.traceData
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-tracedata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/sm-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const singleNssaiParam = req.query['single-nssai'] as string | undefined;
  const dnn = req.query['dnn'] as string | undefined;
  const plmnIdParam = req.query['plmn-id'] as string | undefined;
  const disasterRoamingInd = req.query['disaster-roaming-ind'] === 'true';
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let singleNssai: Snssai | undefined;
  if (singleNssaiParam) {
    try {
      singleNssai = JSON.parse(singleNssaiParam) as Snssai;
      if (typeof singleNssai.sst !== 'number') {
        return res.status(400).json(createInvalidParameterError('Invalid single-nssai format'));
      }
    } catch (e) {
      return res.status(400).json(createInvalidParameterError('Invalid single-nssai JSON format'));
    }
  }

  let plmnId: PlmnId | undefined;
  if (plmnIdParam) {
    try {
      plmnId = JSON.parse(plmnIdParam) as PlmnId;
      if (!plmnId.mcc || !plmnId.mnc) {
        return res.status(400).json(createInvalidParameterError('Invalid plmn-id format'));
      }
    } catch (e) {
      return res.status(400).json(createInvalidParameterError('Invalid plmn-id JSON format'));
    }
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.smData) {
    const defaultSnssai: Snssai = { sst: 1, sd: '000001' };
    const targetSnssai = singleNssai || defaultSnssai;
    
    const sessionManagementData: SessionManagementSubscriptionData = {
      singleNssai: targetSnssai,
      dnnConfigurations: {
        'internet': {
          pduSessionTypes: {
            defaultSessionType: PduSessionType.IPV4V6,
            allowedSessionTypes: [PduSessionType.IPV4, PduSessionType.IPV6, PduSessionType.IPV4V6]
          },
          sscModes: {
            defaultSscMode: SscMode.SSC_MODE_1,
            allowedSscModes: [SscMode.SSC_MODE_1, SscMode.SSC_MODE_2, SscMode.SSC_MODE_3]
          },
          fiveGQosProfile: {
            fiveQi: 9,
            arp: {
              priorityLevel: 8,
              preemptCap: PreemptionCapability.MAY_PREEMPT,
              preemptVuln: PreemptionVulnerability.NOT_PREEMPTABLE
            }
          },
          sessionAmbr: {
            uplink: '500 Mbps',
            downlink: '1000 Mbps'
          }
        },
        'ims': {
          pduSessionTypes: {
            defaultSessionType: PduSessionType.IPV4V6,
            allowedSessionTypes: [PduSessionType.IPV4V6]
          },
          sscModes: {
            defaultSscMode: SscMode.SSC_MODE_1
          },
          fiveGQosProfile: {
            fiveQi: 5,
            arp: {
              priorityLevel: 2,
              preemptCap: PreemptionCapability.MAY_PREEMPT,
              preemptVuln: PreemptionVulnerability.NOT_PREEMPTABLE
            },
            priorityLevel: 1
          },
          sessionAmbr: {
            uplink: '200 Mbps',
            downlink: '200 Mbps'
          }
        }
      }
    };

    storedData.smData = [sessionManagementData];
    await setSubscriptionData(supi, storedData);
  }

  let response: SmSubsData;
  
  if (singleNssai || dnn) {
    const filteredData: SessionManagementSubscriptionData[] = [];
    
    if (Array.isArray(storedData.smData)) {
      for (const smData of storedData.smData) {
        let matches = true;
        
        if (singleNssai) {
          if (smData.singleNssai.sst !== singleNssai.sst || 
              (singleNssai.sd && smData.singleNssai.sd !== singleNssai.sd)) {
            matches = false;
          }
        }
        
        if (dnn && matches) {
          if (!smData.dnnConfigurations || !smData.dnnConfigurations[dnn]) {
            matches = false;
          } else {
            const filteredDnnConfigs: Record<string, any> = {};
            filteredDnnConfigs[dnn] = smData.dnnConfigurations[dnn];
            filteredData.push({
              ...smData,
              dnnConfigurations: filteredDnnConfigs
            });
            continue;
          }
        }
        
        if (matches) {
          filteredData.push(smData);
        }
      }
      response = filteredData;
    } else {
      response = storedData.smData;
    }
  } else {
    response = storedData.smData;
  }

  if (Array.isArray(response) && response.length === 0) {
    return res.status(404).json(createNotFoundError(`Session Management Subscription Data not found for SUPI: ${supi}`));
  }

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-smdata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/sms-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const supportedFeatures = req.query['supported-features'] as string | undefined;
  const plmnIdParam = req.query['plmn-id'] as string | undefined;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let plmnId: PlmnId | undefined;
  if (plmnIdParam) {
    try {
      plmnId = JSON.parse(plmnIdParam) as PlmnId;
      if (!plmnId.mcc || !plmnId.mnc) {
        return res.status(400).json(createInvalidParameterError('Invalid plmn-id format'));
      }
    } catch (e) {
      return res.status(400).json(createInvalidParameterError('Invalid plmn-id JSON format'));
    }
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.smsSubsData) {
    return res.status(404).json(createNotFoundError(`SMS Subscription Data not found for SUPI: ${supi}`));
  }

  const response: SmsSubscriptionData = {
    ...storedData.smsSubsData
  };

  if (supportedFeatures) {
    response.supportedFeatures = supportedFeatures;
  }

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-smsdata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/sms-mng-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const supportedFeatures = req.query['supported-features'] as string | undefined;
  const plmnIdParam = req.query['plmn-id'] as string | undefined;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let plmnId: PlmnId | undefined;
  if (plmnIdParam) {
    try {
      plmnId = JSON.parse(plmnIdParam) as PlmnId;
      if (!plmnId.mcc || !plmnId.mnc) {
        return res.status(400).json(createInvalidParameterError('Invalid plmn-id format'));
      }
    } catch (e) {
      return res.status(400).json(createInvalidParameterError('Invalid plmn-id JSON format'));
    }
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.smsMngData) {
    storedData.smsMngData = {
      mtSmsSubscribed: true,
      mtSmsBarringAll: false,
      mtSmsBarringRoaming: false,
      moSmsSubscribed: true,
      moSmsBarringAll: false,
      moSmsBarringRoaming: false
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: SmsManagementSubscriptionData = {
    ...storedData.smsMngData
  };

  if (supportedFeatures) {
    response.supportedFeatures = supportedFeatures;
  }

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-smsmngdata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:ueId/lcs-privacy-data', async (req: Request, res: Response) => {
  const { ueId } = req.params;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'msisdn', 'extid', 'gci', 'gli'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  let storedData = await getSubscriptionData(ueId);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${ueId.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(ueId, storedData);
  }

  if (!storedData.lcsPrivacyData) {
    storedData.lcsPrivacyData = {
      lpi: {
        locationPrivacyInd: LocationPrivacyInd.LOCATION_ALLOWED,
        validTimePeriod: {
          startTime: new Date().toISOString(),
          endTime: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
        }
      },
      unrelatedClass: {
        defaultUnrelatedClass: {
          privacyCheckRelatedAction: PrivacyCheckRelatedAction.LOCATION_ALLOWED_WITH_NOTIFICATION
        }
      },
      plmnOperatorClasses: [
        {
          lcsClientClass: LcsClientClass.BROADCAST_SERVICE,
          lcsClientIds: ['broadcast-client-1']
        },
        {
          lcsClientClass: LcsClientClass.OM_IN_HPLMN,
          lcsClientIds: ['om-hplmn-client-1', 'om-hplmn-client-2']
        }
      ]
    };
    await setSubscriptionData(ueId, storedData);
  }

  const response: LcsPrivacyData = {
    ...storedData.lcsPrivacyData
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${ueId}-lcsprivacydata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/lcs-mo-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.lcsMoData) {
    storedData.lcsMoData = {
      allowedServiceClasses: [
        LcsMoServiceClass.BASIC_SELF_LOCATION,
        LcsMoServiceClass.AUTONOMOUS_SELF_LOCATION
      ],
      moAssistanceDataTypes: {
        locationAssistanceType: 'A-GPS,A-GNSS'
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: LcsMoData = {
    ...storedData.lcsMoData
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-lcsmodata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/lcs-bca-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const plmnId = req.query['plmn-id'] as string | undefined;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.lcsBroadcastAssistanceTypesData) {
    storedData.lcsBroadcastAssistanceTypesData = {
      locationAssistanceType: 'A-GPS,A-GNSS,OTDOA,ECID'
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: LcsBroadcastAssistanceTypesData = {
    ...storedData.lcsBroadcastAssistanceTypesData
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-lcsbcadata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/lcs-subscription-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.lcsSubscriptionData) {
    storedData.lcsSubscriptionData = {
      configuredLmfId: `lmf-${supi.slice(-8)}`,
      pruInd: PruInd.NON_PRU,
      lpHapType: 'standard',
      userPlanePosIndLmf: false
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: LcsSubscriptionData = {
    ...storedData.lcsSubscriptionData
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-lcssubsdata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/v2x-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.v2xData) {
    storedData.v2xData = {
      nrV2xServicesAuth: {
        vehicleUe: true,
        pedestrianUe: false,
        v2xPermission: {
          v2xCommunicationPermission: true,
          v2xMessagingPermission: true
        }
      },
      lteV2xServicesAuth: {
        vehicleUe: true,
        pedestrianUe: false,
        v2xPermission: {
          v2xCommunicationPermission: true,
          v2xMessagingPermission: true
        }
      },
      nrUePc5Ambr: '100 Mbps',
      ltePc5Ambr: '50 Mbps'
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: V2xSubscriptionData = {
    ...storedData.v2xData
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-v2xdata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/prose-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.proseData) {
    storedData.proseData = {
      proseServiceAuth: {
        proseDirectDiscoveryAuth: true,
        proseDirectCommunicationAuth: true,
        proseL2RelayAuth: false,
        proseL3RelayAuth: false,
        proseL2RemoteAuth: false
      },
      nrUePc5Ambr: '100 Mbps',
      proseAllowedPlmn: [
        {
          visitedPlmn: {
            mcc: '001',
            mnc: '01'
          }
        }
      ]
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: ProseSubscriptionData = {
    ...storedData.proseData
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-prosedata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/5mbs-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.mbsData) {
    storedData.mbsData = {
      mbsAllowed: true,
      mbsSessionIdList: [
        `mbs-session-${supi.slice(-8)}-001`,
        `mbs-session-${supi.slice(-8)}-002`
      ]
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: MbsSubscriptionData = {
    ...storedData.mbsData
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-mbsdata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/uc-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const ucPurposeParam = req.query['uc-purpose'] as string | undefined;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  if (ucPurposeParam && !Object.values(UcPurpose).includes(ucPurposeParam as UcPurpose)) {
    return res.status(400).json(createInvalidParameterError('Invalid uc-purpose value'));
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.ucData) {
    storedData.ucData = {
      userConsentPerPurposeList: {
        [UcPurpose.ANALYTICS]: UserConsent.CONSENT_GIVEN,
        [UcPurpose.MODEL_TRAINING]: UserConsent.CONSENT_NOT_GIVEN,
        [UcPurpose.NW_CAP_EXPOSURE]: UserConsent.CONSENT_GIVEN,
        [UcPurpose.EDGEAPP_UE_LOCATION]: UserConsent.CONSENT_NOT_GIVEN
      }
    };
  }

  const response: UcSubscriptionData = { ...storedData.ucData };

  if (ucPurposeParam) {
    const ucPurpose = ucPurposeParam as UcPurpose;
    if (response.userConsentPerPurposeList && response.userConsentPerPurposeList[ucPurpose] !== undefined) {
      response.userConsentPerPurposeList = {
        [ucPurpose]: response.userConsentPerPurposeList[ucPurpose]
      };
    } else {
      response.userConsentPerPurposeList = {};
    }
  }

  res.status(200).json(response);
});

router.post('/:ueId/sdm-subscriptions', async (req: Request, res: Response) => {
  const { ueId } = req.params;
  const sharedDataIds = req.query['shared-data-ids'] as string | undefined;

  if (!validateUeIdentity(ueId)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const subscriptionRequest = req.body as SdmSubscription;

  if (!subscriptionRequest.nfInstanceId) {
    return res.status(400).json(createMissingParameterError('nfInstanceId is required'));
  }

  if (!subscriptionRequest.callbackReference) {
    return res.status(400).json(createMissingParameterError('callbackReference is required'));
  }

  if (!subscriptionRequest.monitoredResourceUris || subscriptionRequest.monitoredResourceUris.length === 0) {
    return res.status(400).json(createMissingParameterError('monitoredResourceUris is required and must not be empty'));
  }

  const subscriptionId = `sub-${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;

  const subscription: SdmSubscription = {
    ...subscriptionRequest,
    subscriptionId
  };

  await setSdmSubscription(ueId, subscriptionId, subscription);

  const locationUri = `/nudm-sdm/v2/${ueId}/sdm-subscriptions/${subscriptionId}`;

  res.status(201).header('Location', locationUri).json(subscription);
});

router.delete('/:ueId/sdm-subscriptions/:subscriptionId', async (req: Request, res: Response) => {
  const { ueId, subscriptionId } = req.params;

  if (!validateUeIdentity(ueId, undefined, true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const hasSubscription = await hasSdmSubscription(ueId, subscriptionId);

  if (!hasSubscription) {
    return res.status(404).json(createNotFoundError('Subscription not found'));
  }

  await deleteSdmSubscription(ueId, subscriptionId);

  res.status(204).send();
});

router.patch('/:ueId/sdm-subscriptions/:subscriptionId', async (req: Request, res: Response) => {
  const { ueId, subscriptionId } = req.params;
  const supportedFeatures = req.query['supported-features'] as string | undefined;

  if (!validateUeIdentity(ueId, undefined, true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  const currentSubscription = await getSdmSubscription(ueId, subscriptionId);

  if (!currentSubscription) {
    return res.status(404).json(createNotFoundError('Subscription not found'));
  }

  const modification = req.body as SdmSubsModification;

  if (modification.expires !== undefined) {
    currentSubscription.expires = modification.expires;
  }

  if (modification.monitoredResourceUris !== undefined) {
    if (modification.monitoredResourceUris.length === 0) {
      return res.status(403).json(createForbiddenError('monitoredResourceUris cannot be empty'));
    }
    currentSubscription.monitoredResourceUris = modification.monitoredResourceUris;
  }

  await setSdmSubscription(ueId, subscriptionId, currentSubscription);

  if (supportedFeatures) {
    currentSubscription.supportedFeatures = supportedFeatures;
  }

  res.status(200).json(currentSubscription);
});

router.get('/:ueId/id-translation-result', async (req: Request, res: Response) => {
  const { ueId } = req.params;
  const supportedFeatures = req.query['supported-features'] as string | undefined;
  const afId = req.query['af-id'] as string | undefined;
  const appPortIdParam = req.query['app-port-id'] as string | undefined;
  const afServiceId = req.query['af-service-id'] as string | undefined;
  const mtcProviderInfoParam = req.query['mtc-provider-info'] as string | undefined;
  const requestedGpsiType = req.query['requested-gpsi-type'] as GpsiType | undefined;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'msisdn', 'extid', 'gci', 'gli'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  let appPortId: AppPortId | undefined;
  if (appPortIdParam) {
    try {
      appPortId = JSON.parse(appPortIdParam) as AppPortId;
    } catch (e) {
      return res.status(400).json(createInvalidParameterError('Invalid app-port-id JSON format'));
    }
  }

  if (requestedGpsiType && !Object.values(GpsiType).includes(requestedGpsiType)) {
    return res.status(400).json(createInvalidParameterError('Invalid requested-gpsi-type value'));
  }

  const isSupi = ueId.startsWith('imsi-') || ueId.startsWith('nai-');
  const isGpsi = ueId.startsWith('msisdn-') || ueId.startsWith('extid-');

  if (!isSupi && !isGpsi) {
    return res.status(404).json(createNotFoundError('User not found'));
  }

  let result: IdTranslationResult;

  if (isSupi) {
    const supi = ueId;
    
    let storedData = await getSubscriptionData(supi);
    
    if (!storedData) {
      storedData = {
        amData: {
          gpsis: [`msisdn-${supi.slice(-10)}`],
          subscribedUeAmbr: {
            uplink: '1000 Mbps',
            downlink: '2000 Mbps'
          },
          nssai: {
            defaultSingleNssais: [
              { sst: 1, sd: '000001' }
            ],
            singleNssais: [
              { sst: 1, sd: '000001' },
              { sst: 2, sd: '000002' }
            ]
          },
          ratRestrictions: []
        },
        smfSelData: {
          subscribedSnssaiInfos: {
            '1-000001': {
              dnnInfos: [
                {
                  dnn: 'internet',
                  defaultDnnIndicator: true
                }
              ]
            }
          }
        },
        smsSubsData: {
          smsSubscribed: true
        }
      };
      await setSubscriptionData(supi, storedData);
    }

    const gpsis = storedData.amData?.gpsis || [];
    let primaryGpsi: string | undefined;

    if (requestedGpsiType === GpsiType.MSISDN) {
      primaryGpsi = gpsis.find(g => g.startsWith('msisdn-'));
    } else if (requestedGpsiType === GpsiType.EXT_ID) {
      primaryGpsi = gpsis.find(g => g.startsWith('extid-'));
    } else if (requestedGpsiType === GpsiType.EXT_GROUP_ID) {
      primaryGpsi = gpsis.find(g => g.startsWith('extgroupid-'));
    } else {
      primaryGpsi = gpsis[0];
    }

    result = {
      supi: supi,
      gpsi: primaryGpsi,
      additionalGpsis: gpsis.filter(g => g !== primaryGpsi)
    };

    if (supportedFeatures) {
      result.supportedFeatures = supportedFeatures;
    }
  } else {
    const gpsi = ueId;
    
    let foundSupi: string | undefined;
    
    const map = await getAllSubscriptionData();
    for (const [supi, data] of map.entries()) {
      if (data.amData?.gpsis?.includes(gpsi)) {
        foundSupi = supi;
        break;
      }
    }

    if (!foundSupi) {
      foundSupi = `imsi-${gpsi.slice(-15).padStart(15, '0')}`;
      
      const storedData: SubscriptionDataSets = {
        amData: {
          gpsis: [gpsi],
          subscribedUeAmbr: {
            uplink: '1000 Mbps',
            downlink: '2000 Mbps'
          },
          nssai: {
            defaultSingleNssais: [
              { sst: 1, sd: '000001' }
            ],
            singleNssais: [
              { sst: 1, sd: '000001' },
              { sst: 2, sd: '000002' }
            ]
          },
          ratRestrictions: []
        },
        smfSelData: {
          subscribedSnssaiInfos: {
            '1-000001': {
              dnnInfos: [
                {
                  dnn: 'internet',
                  defaultDnnIndicator: true
                }
              ]
            }
          }
        },
        smsSubsData: {
          smsSubscribed: true
        }
      };
      await setSubscriptionData(foundSupi, storedData);
    }

    const storedData = await getSubscriptionData(foundSupi);
    const allGpsis = storedData?.amData?.gpsis || [];
    const otherGpsis = allGpsis.filter(g => g !== gpsi);

    result = {
      supi: foundSupi,
      gpsi: otherGpsis.length > 0 ? otherGpsis[0] : undefined,
      additionalGpsis: otherGpsis.slice(1)
    };

    if (supportedFeatures) {
      result.supportedFeatures = supportedFeatures;
    }
  }

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${ueId}-idtranslation-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(result);
});

router.put('/:supi/am-data/sor-ack', async (req: Request, res: Response) => {
  const { supi } = req.params;

  if (!validateUeIdentity(supi, ['imsi', 'nai'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  const acknowledgeInfo = req.body as AcknowledgeInfo;

  if (!acknowledgeInfo.provisioningTime) {
    return res.status(400).json(createMissingParameterError('provisioningTime is required'));
  }

  const storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    return res.status(404).json(createNotFoundError('User not found'));
  }

  return res.status(204).send();
});

router.put('/:supi/am-data/upu-ack', async (req: Request, res: Response) => {
  const { supi } = req.params;

  if (!validateUeIdentity(supi, ['imsi', 'nai'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  const acknowledgeInfo = req.body as AcknowledgeInfo;

  if (!acknowledgeInfo.provisioningTime) {
    return res.status(400).json(createMissingParameterError('provisioningTime is required'));
  }

  const storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    return res.status(404).json(createNotFoundError('User not found'));
  }

  return res.status(204).send();
});

router.put('/:supi/am-data/subscribed-snssais-ack', async (req: Request, res: Response) => {
  const { supi } = req.params;

  if (!validateUeIdentity(supi, ['imsi', 'nai'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  const acknowledgeInfo = req.body as AcknowledgeInfo;

  if (!acknowledgeInfo.provisioningTime) {
    return res.status(400).json(createMissingParameterError('provisioningTime is required'));
  }

  const storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    return res.status(404).json(createNotFoundError('User not found'));
  }

  return res.status(204).send();
});

router.put('/:supi/am-data/cag-ack', async (req: Request, res: Response) => {
  const { supi } = req.params;

  if (!validateUeIdentity(supi, ['imsi', 'nai'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  const acknowledgeInfo = req.body as AcknowledgeInfo;

  if (!acknowledgeInfo.provisioningTime) {
    return res.status(400).json(createMissingParameterError('provisioningTime is required'));
  }

  const storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    return res.status(404).json(createNotFoundError('User not found'));
  }

  return res.status(204).send();
});

router.post('/:supi/am-data/update-sor', async (req: Request, res: Response) => {
  const { supi } = req.params;

  if (!validateUeIdentity(supi, ['imsi', 'nai'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  const sorUpdateInfo = req.body as SorUpdateInfo;

  if (!sorUpdateInfo.vplmnId) {
    return res.status(400).json(createMissingParameterError('vplmnId is required'));
  }

  if (!sorUpdateInfo.vplmnId.mcc || !sorUpdateInfo.vplmnId.mnc) {
    return res.status(400).json(createInvalidParameterError('vplmnId must contain mcc and mnc'));
  }

  const storedData = await getSubscriptionData(supi);
  
  if (!storedData || !storedData.amData) {
    return res.status(404).json(createNotFoundError('User not found'));
  }

  if (!storedData.amData.sorInfo) {
    storedData.amData.sorInfo = {
      ackInd: true,
      provisioningTime: new Date().toISOString(),
      sorMacIausf: 'mock-sor-mac-iausf',
      countersor: '1'
    };
  }

  return res.status(200).json(storedData.amData.sorInfo);
});

router.get('/shared-data', async (req: Request, res: Response) => {
  const sharedDataIdsParam = req.query['shared-data-ids'] as string | undefined;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!sharedDataIdsParam) {
    return res.status(400).json(createMissingParameterError('shared-data-ids query parameter is required'));
  }

  const sharedDataIds = sharedDataIdsParam.split(',').map(id => id.trim() as SharedDataId);

  if (sharedDataIds.length === 0) {
    return res.status(400).json(createInvalidParameterError('shared-data-ids must contain at least one ID'));
  }

  const result: SharedData[] = [];

  for (const sharedDataId of sharedDataIds) {
    const sharedData = await getSharedData(sharedDataId);
    if (sharedData) {
      result.push(sharedData);
    }
  }

  if (result.length === 0) {
    return res.status(404).json(createNotFoundError('Shared data not found'));
  }

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"shared-data-${sharedDataIds.join('-')}-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(result);
});

router.post('/shared-data-subscriptions', async (req: Request, res: Response) => {
  const subscriptionRequest = req.body as SdmSubscription;

  if (!subscriptionRequest.nfInstanceId) {
    return res.status(400).json(createMissingParameterError('nfInstanceId is required'));
  }

  if (!subscriptionRequest.callbackReference) {
    return res.status(400).json(createMissingParameterError('callbackReference is required'));
  }

  if (!subscriptionRequest.monitoredResourceUris || subscriptionRequest.monitoredResourceUris.length === 0) {
    return res.status(400).json(createMissingParameterError('monitoredResourceUris is required and must not be empty'));
  }

  const subscriptionId = `sub-${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;

  const subscription: SdmSubscription = {
    ...subscriptionRequest,
    subscriptionId
  };

  await setSharedDataSubscription(subscriptionId, subscription);

  const locationUri = `/nudm-sdm/v2/shared-data-subscriptions/${subscriptionId}`;

  res.status(201).header('Location', locationUri).json(subscription);
});

router.delete('/shared-data-subscriptions/:subscriptionId', async (req: Request, res: Response) => {
  const { subscriptionId } = req.params;

  const hasSubscription = await hasSharedDataSubscription(subscriptionId);

  if (!hasSubscription) {
    return res.status(404).json(createNotFoundError('Subscription not found'));
  }

  await deleteSharedDataSubscription(subscriptionId);

  res.status(204).send();
});

router.patch('/shared-data-subscriptions/:subscriptionId', async (req: Request, res: Response) => {
  const { subscriptionId } = req.params;
  const supportedFeatures = req.query['supported-features'] as string | undefined;

  const currentSubscription = await getSharedDataSubscription(subscriptionId);

  if (!currentSubscription) {
    return res.status(404).json(createNotFoundError('Subscription not found'));
  }

  const modification = req.body as SdmSubsModification;

  if (modification.expires !== undefined) {
    currentSubscription.expires = modification.expires;
  }

  if (modification.monitoredResourceUris !== undefined) {
    if (modification.monitoredResourceUris.length === 0) {
      return res.status(403).json(createForbiddenError('monitoredResourceUris cannot be empty'));
    }
    currentSubscription.monitoredResourceUris = modification.monitoredResourceUris;
  }

  if (supportedFeatures) {
    currentSubscription.supportedFeatures = supportedFeatures;
  }

  await setSharedDataSubscription(subscriptionId, currentSubscription);

  res.status(200).json(currentSubscription);
});

router.get('/group-data/group-identifiers', async (req: Request, res: Response) => {
  const extGroupId = req.query['ext-group-id'] as string | undefined;
  const intGroupId = req.query['int-group-id'] as string | undefined;
  const ueIdInd = req.query['ue-id-ind'] === 'true';
  const afId = req.query['af-id'] as string | undefined;
  const ifNoneMatch = req.get('If-None-Match');
  const ifModifiedSince = req.get('If-Modified-Since');

  if (!extGroupId && !intGroupId) {
    return res.status(400).json(createMissingParameterError('Either ext-group-id or int-group-id must be provided'));
  }

  let groupData = await getGroupIdentifiers(extGroupId, intGroupId);

  if (!groupData) {
    if (extGroupId) {
      groupData = {
        extGroupId: extGroupId,
        intGroupId: `group-${extGroupId.split('@')[0]}`
      };
    } else if (intGroupId) {
      groupData = {
        intGroupId: intGroupId,
        extGroupId: `${intGroupId.replace('group-', '')}@example.com` as ExtGroupId
      };
    }

    if (ueIdInd && groupData) {
      groupData.ueIdList = [
        {
          supi: `imsi-123456789012345`,
          gpsiList: [`msisdn-1234567890`]
        },
        {
          supi: `imsi-123456789012346`,
          gpsiList: [`msisdn-1234567891`]
        }
      ];
    }

    if (groupData) {
      await setGroupIdentifiers(extGroupId, intGroupId, groupData);
    }
  } else {
    if (ueIdInd && !groupData.ueIdList) {
      groupData.ueIdList = [
        {
          supi: `imsi-123456789012345`,
          gpsiList: [`msisdn-1234567890`]
        },
        {
          supi: `imsi-123456789012346`,
          gpsiList: [`msisdn-1234567891`]
        }
      ];
      await setGroupIdentifiers(extGroupId, intGroupId, groupData);
    }
  }

  if (!groupData) {
    return res.status(404).json(createNotFoundError('Group identifier not found'));
  }

  if (afId) {
    const allowedAfIds = ['AF001', 'AF002', 'AF003'];
    if (!allowedAfIds.includes(afId)) {
      return res.status(403).json(createForbiddenError('AF not allowed to access this group'));
    }
  }

  const responseData: GroupIdentifiers = { ...groupData };

  const responseHeaders: Record<string, string> = {};

  const lookupKey = extGroupId || intGroupId!;
  const etag = `"${lookupKey}-${Date.now()}"`;
  responseHeaders['ETag'] = etag;
  
  const lastModified = new Date().toUTCString();
  responseHeaders['Last-Modified'] = lastModified;
  
  responseHeaders['Cache-Control'] = 'max-age=3600';

  if (ifNoneMatch && ifNoneMatch === etag) {
    return res.status(304).send();
  }

  if (ifModifiedSince) {
    const modifiedSinceDate = new Date(ifModifiedSince);
    const lastModifiedDate = new Date(lastModified);
    if (lastModifiedDate <= modifiedSinceDate) {
      return res.status(304).send();
    }
  }

  res.set(responseHeaders).status(200).json(responseData);
});

router.get('/shared-data/:sharedDataId', async (req: Request, res: Response) => {
  const { sharedDataId } = req.params;
  const supportedFeatures = req.query['supported-features'] as string | undefined;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  const sharedData = await getSharedData(sharedDataId as SharedDataId);

  if (!sharedData) {
    return res.status(404).json(createNotFoundError(`Shared data not found for sharedDataId: ${sharedDataId}`));
  }

  const responseData: SharedData = {
    ...sharedData,
    ...(supportedFeatures && { supportedFeatures })
  };

  const responseHeaders: Record<string, string> = {};
  
  const etag = `"${Buffer.from(JSON.stringify(responseData)).toString('base64').substring(0, 32)}"`;
  responseHeaders['ETag'] = etag;
  
  const lastModified = new Date().toUTCString();
  responseHeaders['Last-Modified'] = lastModified;
  
  responseHeaders['Cache-Control'] = 'max-age=3600';

  if (ifNoneMatch && ifNoneMatch === etag) {
    return res.status(304).send();
  }

  if (ifModifiedSince) {
    const modifiedSinceDate = new Date(ifModifiedSince);
    const lastModifiedDate = new Date(lastModified);
    if (lastModifiedDate <= modifiedSinceDate) {
      return res.status(304).send();
    }
  }

  res.set(responseHeaders).status(200).json(responseData);
});

router.get('/multiple-identifiers', async (req: Request, res: Response) => {
  const gpsiListParam = req.query['gpsi-list'] as string | undefined;
  const supiListParam = req.query['supi-list'] as string | undefined;
  const afId = req.query['af-id'] as string | undefined;
  const appPortIdParam = req.query['app-port-id'] as string | undefined;
  const mtcProviderInfoParam = req.query['mtc-provider-info'] as string | undefined;
  const requestedGpsiType = req.query['requested-gpsi-type'] as GpsiType | undefined;

  if (!gpsiListParam && !supiListParam) {
    return res.status(400).json(createMissingParameterError('Either gpsi-list or supi-list must be provided'));
  }

  let appPortId: AppPortId | undefined;
  if (appPortIdParam) {
    try {
      appPortId = JSON.parse(appPortIdParam) as AppPortId;
    } catch (e) {
      return res.status(400).json(createInvalidParameterError('Invalid app-port-id JSON format'));
    }
  }

  if (requestedGpsiType && !Object.values(GpsiType).includes(requestedGpsiType)) {
    return res.status(400).json(createInvalidParameterError('Invalid requested-gpsi-type value'));
  }

  const ueIdList: Record<string, SupiInfo> = {};

  if (gpsiListParam) {
    const gpsiList = gpsiListParam.split(',').map(gpsi => gpsi.trim());

    if (gpsiList.length === 0) {
      return res.status(400).json(createInvalidParameterError('gpsi-list must contain at least one GPSI'));
    }

    for (const gpsi of gpsiList) {
      if (!validateUeIdentity(gpsi, ['msisdn', 'extid', 'extgroupid'])) {
        return res.status(400).json(createInvalidParameterError(`Invalid GPSI format: ${gpsi}`));
      }

      let foundSupis: string[] = [];

      const map = await getAllSubscriptionData();
      for (const [supi, data] of map.entries()) {
        if (data.amData?.gpsis?.includes(gpsi)) {
          foundSupis.push(supi);
        }
      }

      if (foundSupis.length === 0) {
        const generatedSupi = `imsi-${gpsi.slice(-15).padStart(15, '0')}`;
        foundSupis.push(generatedSupi);

        const storedData: SubscriptionDataSets = {
          amData: {
            gpsis: [gpsi],
            subscribedUeAmbr: {
              uplink: '1000 Mbps',
              downlink: '2000 Mbps'
            },
            nssai: {
              defaultSingleNssais: [
                { sst: 1, sd: '000001' }
              ],
              singleNssais: [
                { sst: 1, sd: '000001' },
                { sst: 2, sd: '000002' }
              ]
            },
            ratRestrictions: []
          },
          smfSelData: {
            subscribedSnssaiInfos: {
              '1-000001': {
                dnnInfos: [
                  {
                    dnn: 'internet',
                    defaultDnnIndicator: true
                  }
                ]
              }
            }
          },
          smsSubsData: {
            smsSubscribed: true
          }
        };
        await setSubscriptionData(generatedSupi, storedData);
      }

      ueIdList[gpsi] = {
        supiList: foundSupis
      };
    }
  }

  if (supiListParam) {
    const supiList = supiListParam.split(',').map(supi => supi.trim());

    if (supiList.length === 0) {
      return res.status(400).json(createInvalidParameterError('supi-list must contain at least one SUPI'));
    }

    for (const supi of supiList) {
      if (!validateUeIdentity(supi, ['imsi', 'nai'])) {
        return res.status(400).json(createInvalidParameterError(`Invalid SUPI format: ${supi}`));
      }

      let storedData = await getSubscriptionData(supi);

      if (!storedData) {
        storedData = {
          amData: {
            gpsis: [`msisdn-${supi.slice(-10)}`],
            subscribedUeAmbr: {
              uplink: '1000 Mbps',
              downlink: '2000 Mbps'
            },
            nssai: {
              defaultSingleNssais: [
                { sst: 1, sd: '000001' }
              ],
              singleNssais: [
                { sst: 1, sd: '000001' },
                { sst: 2, sd: '000002' }
              ]
            },
            ratRestrictions: []
          },
          smfSelData: {
            subscribedSnssaiInfos: {
              '1-000001': {
                dnnInfos: [
                  {
                    dnn: 'internet',
                    defaultDnnIndicator: true
                  }
                ]
              }
            }
          },
          smsSubsData: {
            smsSubscribed: true
          }
        };
        await setSubscriptionData(supi, storedData);
      }

      const gpsis = storedData.amData?.gpsis || [];
      let primaryGpsi: string | undefined;

      if (requestedGpsiType === GpsiType.MSISDN) {
        primaryGpsi = gpsis.find(g => g.startsWith('msisdn-'));
      } else if (requestedGpsiType === GpsiType.EXT_ID) {
        primaryGpsi = gpsis.find(g => g.startsWith('extid-'));
      } else if (requestedGpsiType === GpsiType.EXT_GROUP_ID) {
        primaryGpsi = gpsis.find(g => g.startsWith('extgroupid-'));
      } else {
        primaryGpsi = gpsis[0];
      }

      if (primaryGpsi) {
        if (!ueIdList[primaryGpsi]) {
          ueIdList[primaryGpsi] = {
            supiList: [supi]
          };
        } else {
          if (!ueIdList[primaryGpsi].supiList.includes(supi)) {
            ueIdList[primaryGpsi].supiList.push(supi);
          }
        }
      }
    }
  }

  if (Object.keys(ueIdList).length === 0) {
    return res.status(404).json(createNotFoundError('No matching identifiers found'));
  }

  const response: UeIdentifiers = {
    ueIdList
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"multiple-identifiers-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/time-sync-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: TimeSyncSubscriptionData = {
    afReqAuthorizations: {
      gptpAllowedInfoList: [
        {
          dnn: 'internet',
          sNssai: { sst: 1, sd: '000001' },
          gptpAllowed: true,
          acceptableInd: false
        }
      ]
    },
    serviceIds: [
      {
        reference: 'time-sync-service-1',
        dnn: 'internet',
        sNssai: { sst: 1, sd: '000001' }
      }
    ]
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-timesync-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/ranging-slpos-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: RangingSlPosSubscriptionData = {
    rangingSlPosAuth: {
      rangingAllowed: true,
      sl1AllowedIndication: true,
      sl2AllowedIndication: false,
      sl3AllowedIndication: false
    },
    rangingSlPosPlmn: [
      {
        rangingSlPosPlmn: {
          mcc: '001',
          mnc: '01'
        }
      }
    ],
    rangingSlPosQos: {
      hAccuracy: 10,
      vAccuracy: 10,
      verticalRequested: false,
      rangingSlPosPriorityLevel: 5,
      rangingSlPosDelayBudget: 100
    }
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-rangingslpos-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:supi/a2x-data', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(supi, ['imsi', 'nai', 'gci', 'gli'])) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  let storedData = await getSubscriptionData(supi);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${supi.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(supi, storedData);
  }

  if (!storedData.a2xData) {
    storedData.a2xData = {
      nrA2xServicesAuth: {
        vehicleUe: true,
        pedestrianUe: false,
        a2xPermission: {
          a2xCommunicationPermission: true,
          a2xMessagingPermission: true
        }
      },
      lteA2xServicesAuth: {
        vehicleUe: true,
        pedestrianUe: false,
        a2xPermission: {
          a2xCommunicationPermission: true,
          a2xMessagingPermission: true
        }
      },
      nrUePc5Ambr: '100 Mbps',
      ltePc5Ambr: '50 Mbps'
    };
    await setSubscriptionData(supi, storedData);
  }

  const response: A2xSubscriptionData = {
    ...storedData.a2xData
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${supi}-a2xdata-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

router.get('/:ueId/rangingsl-privacy-data', async (req: Request, res: Response) => {
  const { ueId } = req.params;
  const ifNoneMatch = req.headers['if-none-match'] as string | undefined;
  const ifModifiedSince = req.headers['if-modified-since'] as string | undefined;

  if (!validateUeIdentity(ueId, ['imsi', 'nai', 'msisdn', 'extid', 'gci', 'gli'], true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueId format'));
  }

  let storedData = await getSubscriptionData(ueId);
  
  if (!storedData) {
    storedData = {
      amData: {
        gpsis: [`msisdn-${ueId.slice(-10)}`],
        subscribedUeAmbr: {
          uplink: '1000 Mbps',
          downlink: '2000 Mbps'
        },
        nssai: {
          defaultSingleNssais: [
            { sst: 1, sd: '000001' }
          ],
          singleNssais: [
            { sst: 1, sd: '000001' },
            { sst: 2, sd: '000002' }
          ]
        },
        ratRestrictions: []
      },
      smfSelData: {
        subscribedSnssaiInfos: {
          '1-000001': {
            dnnInfos: [
              {
                dnn: 'internet',
                defaultDnnIndicator: true
              }
            ]
          }
        }
      },
      smsSubsData: {
        smsSubscribed: true
      }
    };
    await setSubscriptionData(ueId, storedData);
  }

  if (!storedData.rangingSlPrivacyData) {
    storedData.rangingSlPrivacyData = {
      rslppi: {
        rangingSlPrivacyInd: RangingSlPrivacyInd.RANGINGSL_ALLOWED,
        validTimePeriod: {
          startTime: new Date().toISOString(),
          endTime: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
        }
      },
      rangingSlUnrelatedClass: {
        rangingSlDefaultUnrelatedClass: {
          rangingSlPrivacyCheckRelatedAction: RangingSlPrivacyCheckRelatedAction.RANGINGSL_ALLOWED_WITH_NOTIFICATION
        }
      },
      rangingSlPlmnOperatorClasses: [
        {
          rangingSlLcsClientClass: LcsClientClass.BROADCAST_SERVICE,
          lcsClientIds: ['broadcast-client-1']
        },
        {
          rangingSlLcsClientClass: LcsClientClass.OM_IN_HPLMN,
          lcsClientIds: ['om-hplmn-client-1', 'om-hplmn-client-2']
        }
      ]
    };
    await setSubscriptionData(ueId, storedData);
  }

  const response: RangingSlPrivacyData = {
    ...storedData.rangingSlPrivacyData
  };

  const headers: Record<string, string> = {
    'Cache-Control': 'max-age=3600',
    'ETag': `"${ueId}-rangingslprivacy-v1"`,
    'Last-Modified': new Date().toUTCString()
  };

  res.set(headers);
  return res.status(200).json(response);
});

export default router;

