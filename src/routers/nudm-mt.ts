import { Router, Request, Response } from 'express';
import { getCollection } from '../db/mongodb';
import { 
  UeContextInfo, 
  FiveGSrvccInfo, 
  FiveGsUserState,
  UeInfo,
  LocationInfoRequest, 
  LocationInfoResult,
  Ncgi,
  Tai,
  ProblemDetails
} from '../types/nudm-mt-types';
import { PlmnId, RatType, createInvalidParameterError } from '../types/common-types';

const router = Router();

interface StoredUeInfo {
  _id: string;
  tadsInfo?: UeContextInfo;
  userState?: FiveGsUserState;
  fiveGSrvccInfo?: FiveGSrvccInfo;
  locationInfo?: LocationInfoResult;
}

router.get('/:supi', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const fields = req.query.fields;
  const supportedFeatures = req.query['supported-features'];

  const supiPattern = /^(imsi-[0-9]{5,15}|nai-.+)$/;
  if (!supiPattern.test(supi)) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  if (!fields) {
    return res.status(400).json({
      type: 'urn:3gpp:error:missing-parameter',
      title: 'Bad Request',
      status: 400,
      detail: 'Missing required query parameter: fields',
      cause: 'MANDATORY_IE_MISSING'
    });
  }

  let fieldsArray: string[];
  if (Array.isArray(fields)) {
    fieldsArray = fields.filter(f => typeof f === 'string') as string[];
  } else if (typeof fields === 'string') {
    fieldsArray = fields.split(',').map(f => f.trim());
  } else {
    fieldsArray = [];
  }
  
  if (fieldsArray.length === 0) {
    return res.status(400).json(createInvalidParameterError('fields parameter must contain at least one item'));
  }

  let ueInfo: StoredUeInfo | null;
  try {
    const collection = getCollection<StoredUeInfo>();
    ueInfo = await collection.findOne({ _id: supi });
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Database operation failed'
    } as ProblemDetails);
  }

  if (!ueInfo) {
    return res.status(404).json({
      type: 'urn:3gpp:error:user-not-found',
      title: 'Not Found',
      status: 404,
      detail: 'User not found',
      cause: 'USER_NOT_FOUND'
    } as ProblemDetails);
  }

  const response: Partial<UeInfo> = {};
  let hasRequestedData = false;
  
  for (const field of fieldsArray) {
    if (field === 'tadsInfo' && ueInfo.tadsInfo) {
      response.tadsInfo = ueInfo.tadsInfo;
      hasRequestedData = true;
    } else if (field === 'userState' && ueInfo.userState) {
      response.userState = ueInfo.userState;
      hasRequestedData = true;
    } else if (field === 'fiveGSrvccInfo' && ueInfo.fiveGSrvccInfo) {
      response.fiveGSrvccInfo = ueInfo.fiveGSrvccInfo;
      hasRequestedData = true;
    }
  }

  if (!hasRequestedData) {
    return res.status(404).json({
      type: 'urn:3gpp:error:data-not-found',
      title: 'Not Found',
      status: 404,
      detail: 'Requested data not found',
      cause: 'DATA_NOT_FOUND'
    } as ProblemDetails);
  }

  res.status(200).json(response);
});

router.post('/:supi/loc-info/provide-loc-info', async (req: Request, res: Response) => {
  const { supi } = req.params;
  const body = req.body as LocationInfoRequest;

  const supiPattern = /^(imsi-[0-9]{5,15}|nai-.+|.+)$/;
  if (!supiPattern.test(supi)) {
    return res.status(400).json(createInvalidParameterError('Invalid supi format'));
  }

  if (!body || typeof body !== 'object') {
    return res.status(400).json(createInvalidParameterError('Request body must be a valid JSON object'));
  }

  const {
    req5gsLoc = false,
    reqCurrentLoc = false,
    reqRatType = false,
    reqTimeZone = false,
    reqServingNode = false,
    supportedFeatures
  } = body;

  let ueInfo: StoredUeInfo | null;
  try {
    const collection = getCollection<StoredUeInfo>();
    ueInfo = await collection.findOne({ _id: supi });
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Database operation failed'
    } as ProblemDetails);
  }

  if (!ueInfo) {
    return res.status(404).json({
      type: 'urn:3gpp:error:user-not-found',
      title: 'Not Found',
      status: 404,
      detail: 'User not found',
      cause: 'USER_NOT_FOUND'
    } as ProblemDetails);
  }

  if (!ueInfo.locationInfo) {
    return res.status(404).json({
      type: 'urn:3gpp:error:data-not-found',
      title: 'Not Found',
      status: 404,
      detail: 'Location information not found',
      cause: 'DATA_NOT_FOUND'
    } as ProblemDetails);
  }

  const storedLocation = ueInfo.locationInfo;
  const response: Partial<LocationInfoResult> = {
    vPlmnId: storedLocation.vPlmnId
  };

  if ((req5gsLoc || reqCurrentLoc) && (storedLocation.ncgi || storedLocation.tai || storedLocation.ecgi)) {
    if (storedLocation.ncgi) {
      response.ncgi = storedLocation.ncgi;
    }
    if (storedLocation.ecgi) {
      response.ecgi = storedLocation.ecgi;
    }
    if (storedLocation.tai) {
      response.tai = storedLocation.tai;
    }
    if (storedLocation.currentLoc !== undefined) {
      response.currentLoc = storedLocation.currentLoc;
    }
    if (storedLocation.geoInfo) {
      response.geoInfo = storedLocation.geoInfo;
    }
    if (storedLocation.locationAge !== undefined) {
      response.locationAge = storedLocation.locationAge;
    }
  }

  if (reqServingNode) {
    if (storedLocation.amfInstanceId) {
      response.amfInstanceId = storedLocation.amfInstanceId;
    }
    if (storedLocation.smsfInstanceId) {
      response.smsfInstanceId = storedLocation.smsfInstanceId;
    }
  }

  if (reqRatType && storedLocation.ratType) {
    response.ratType = storedLocation.ratType;
  }

  if (reqTimeZone && storedLocation.timezone) {
    response.timezone = storedLocation.timezone;
  }

  if (supportedFeatures) {
    response.supportedFeatures = supportedFeatures;
  }

  res.status(200).json(response);
});

export default router;

