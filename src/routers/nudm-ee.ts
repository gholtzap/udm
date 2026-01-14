import { Router, Request, Response } from 'express';
import { randomUUID } from 'crypto';
import { getCollection } from '../db/mongodb';
import { EeSubscription, CreatedEeSubscription, EventType } from '../types/nudm-ee-types';
import { validateUeIdentity, createInvalidParameterError } from '../types/common-types';

interface PatchOperation {
  op: 'add' | 'remove' | 'replace' | 'move' | 'copy' | 'test';
  path: string;
  value?: any;
  from?: string;
}

interface FailedPatchOperation extends PatchOperation {
  originalError: {
    title: string;
    status: number;
    detail: string;
  };
}

interface StoredEeSubscription extends EeSubscription {
  _id: string;
  ueIdentity: string;
}

const router = Router();

const notImplemented = (req: Request, res: Response) => {
  res.status(501).json({
    title: 'Not Implemented',
    status: 501,
    detail: 'This endpoint is not yet implemented'
  });
};

router.post('/:ueIdentity/ee-subscriptions', async (req: Request, res: Response) => {
  const { ueIdentity } = req.params;
  const eeSubscription: EeSubscription = req.body;

  if (!validateUeIdentity(ueIdentity, undefined, true)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueIdentity format'));
  }

  if (!eeSubscription.callbackReference) {
    return res.status(400).json({
      type: 'urn:3gpp:error:missing-parameter',
      title: 'Bad Request',
      status: 400,
      detail: 'Missing required field: callbackReference',
      cause: 'MANDATORY_IE_MISSING'
    });
  }

  if (!eeSubscription.monitoringConfigurations || 
      Object.keys(eeSubscription.monitoringConfigurations).length === 0) {
    return res.status(400).json({
      type: 'urn:3gpp:error:missing-parameter',
      title: 'Bad Request',
      status: 400,
      detail: 'Missing or empty required field: monitoringConfigurations',
      cause: 'MANDATORY_IE_MISSING'
    });
  }

  const supportedEventTypes = Object.values(EventType);
  const unsupportedEventTypes = Object.values(eeSubscription.monitoringConfigurations)
    .filter(config => !supportedEventTypes.includes(config.eventType));
  
  if (unsupportedEventTypes.length > 0) {
    return res.status(501).json({
      type: 'urn:3gpp:error:not-implemented',
      title: 'Not Implemented',
      status: 501,
      detail: 'One or more monitoring event types are not supported',
      cause: 'UNSUPPORTED_MONITORING_EVENT_TYPE'
    });
  }

  if (eeSubscription.reportingOptions) {
    const { reportMode, maxNumOfReports, samplingRatio, guardTime, reportPeriod } = eeSubscription.reportingOptions;
    const hasUnsupportedOptions = (samplingRatio !== undefined && samplingRatio > 1) || 
                                   (guardTime !== undefined && guardTime > 0) ||
                                   (reportPeriod !== undefined && reportPeriod > 0);
    
    if (hasUnsupportedOptions) {
      return res.status(501).json({
        type: 'urn:3gpp:error:not-implemented',
        title: 'Not Implemented',
        status: 501,
        detail: 'One or more monitoring report options are not supported',
        cause: 'UNSUPPORTED_MONITORING_REPORT_OPTIONS'
      });
    }
  }

  const hasAfId = Object.values(eeSubscription.monitoringConfigurations)
    .some(config => config.afId !== undefined);
  
  if (hasAfId) {
    return res.status(403).json({
      type: 'urn:3gpp:error:forbidden',
      title: 'Forbidden',
      status: 403,
      detail: 'AF is not allowed to monitor this UE',
      cause: 'AF_NOT_ALLOWED'
    });
  }

  const hasMtcProvider = Object.values(eeSubscription.monitoringConfigurations)
    .some(config => config.mtcProviderInformation !== undefined);
  
  if (hasMtcProvider) {
    return res.status(403).json({
      type: 'urn:3gpp:error:forbidden',
      title: 'Forbidden',
      status: 403,
      detail: 'MTC provider is not allowed to monitor this UE',
      cause: 'MTC_PROVIDER_NOT_ALLOWED'
    });
  }


  const subscriptionId = randomUUID();
  
  eeSubscription.subscriptionId = subscriptionId;

  const key = `${ueIdentity}:${subscriptionId}`;
  
  const storedSubscription: StoredEeSubscription = {
    _id: key,
    ueIdentity,
    ...eeSubscription
  };

  try {
    const collection = getCollection<StoredEeSubscription>('ee-subscriptions');
    await collection.insertOne(storedSubscription);
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Failed to create subscription'
    });
  }

  const location = `/nudm-ee/v1/${ueIdentity}/ee-subscriptions/${subscriptionId}`;

  const response: CreatedEeSubscription = {
    eeSubscription: eeSubscription
  };

  res.status(201)
    .header('Location', location)
    .json(response);
});

router.delete('/:ueIdentity/ee-subscriptions/:subscriptionId', async (req: Request, res: Response) => {
  const { ueIdentity, subscriptionId } = req.params;

  if (!validateUeIdentity(ueIdentity)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueIdentity format'));
  }

  const key = `${ueIdentity}:${subscriptionId}`;

  try {
    const collection = getCollection<StoredEeSubscription>('ee-subscriptions');
    const result = await collection.deleteOne({ _id: key });

    if (result.deletedCount === 0) {
      return res.status(404).json({
        type: 'urn:3gpp:error:not-found',
        title: 'Not Found',
        status: 404,
        detail: 'Subscription not found',
        cause: 'SUBSCRIPTION_NOT_FOUND'
      });
    }
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Failed to delete subscription'
    });
  }

  res.status(204).send();
});

router.patch('/:ueIdentity/ee-subscriptions/:subscriptionId', async (req: Request, res: Response) => {
  const { ueIdentity, subscriptionId } = req.params;
  const patchOperations: PatchOperation[] = req.body;
  const supportedFeatures = req.query['supported-features'] as string;

  if (!validateUeIdentity(ueIdentity)) {
    return res.status(400).json(createInvalidParameterError('Invalid ueIdentity format'));
  }

  const key = `${ueIdentity}:${subscriptionId}`;

  let subscription: StoredEeSubscription | null;
  try {
    const collection = getCollection<StoredEeSubscription>('ee-subscriptions');
    subscription = await collection.findOne({ _id: key });
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Database operation failed'
    });
  }

  if (!subscription) {
    return res.status(404).json({
      type: 'urn:3gpp:error:not-found',
      title: 'Not Found',
      status: 404,
      detail: 'Subscription not found',
      cause: 'SUBSCRIPTION_NOT_FOUND'
    });
  }

  if (!Array.isArray(patchOperations) || patchOperations.length === 0) {
    return res.status(400).json({
      type: 'urn:3gpp:error:invalid-parameter',
      title: 'Bad Request',
      status: 400,
      detail: 'Request body must be a non-empty array of patch operations',
      cause: 'INVALID_PARAMETER'
    });
  }

  const failedOperations: FailedPatchOperation[] = [];
  const hasPatchReportFeature = supportedFeatures?.includes('PatchReport') || false;

  for (let i = 0; i < patchOperations.length; i++) {
    const operation = patchOperations[i];
    
    if (!operation.op || !operation.path) {
      failedOperations.push({
        op: operation.op,
        path: operation.path,
        value: operation.value,
        originalError: {
          title: 'Bad Request',
          status: 400,
          detail: 'Missing required fields in patch operation'
        }
      });
      continue;
    }

    try {
      applyPatchOperation(subscription, operation);
    } catch (error: any) {
      failedOperations.push({
        op: operation.op,
        path: operation.path,
        value: operation.value,
        originalError: {
          title: 'Bad Request',
          status: 400,
          detail: error.message || 'Failed to apply patch operation'
        }
      });
    }
  }

  try {
    const collection = getCollection<StoredEeSubscription>('ee-subscriptions');
    await collection.replaceOne({ _id: key }, subscription);
  } catch (error) {
    return res.status(500).json({
      type: 'urn:3gpp:error:internal-error',
      title: 'Internal Server Error',
      status: 500,
      detail: 'Failed to update subscription'
    });
  }

  if (failedOperations.length > 0 && hasPatchReportFeature) {
    return res.status(200).json({
      report: failedOperations.map(op => ({
        op: op.op,
        path: op.path,
        value: op.value,
        originalError: op.originalError
      }))
    });
  }

  res.status(204).send();
});

function applyPatchOperation(obj: any, operation: PatchOperation): void {
  const { op, path, value, from } = operation;
  const pathParts = path.split('/').filter((p: string) => p);

  switch (op) {
    case 'add':
      setValueAtPath(obj, pathParts, value, true);
      break;
    case 'remove':
      removeValueAtPath(obj, pathParts);
      break;
    case 'replace':
      setValueAtPath(obj, pathParts, value, false);
      break;
    case 'move':
      if (!from) throw new Error('Move operation requires "from" field');
      const fromParts = from.split('/').filter((p: string) => p);
      const movedValue = getValueAtPath(obj, fromParts);
      removeValueAtPath(obj, fromParts);
      setValueAtPath(obj, pathParts, movedValue, true);
      break;
    case 'copy':
      if (!from) throw new Error('Copy operation requires "from" field');
      const fromPartsCopy = from.split('/').filter((p: string) => p);
      const copiedValue = getValueAtPath(obj, fromPartsCopy);
      setValueAtPath(obj, pathParts, copiedValue, true);
      break;
    case 'test':
      const currentValue = getValueAtPath(obj, pathParts);
      if (JSON.stringify(currentValue) !== JSON.stringify(value)) {
        throw new Error('Test operation failed: value does not match');
      }
      break;
    default:
      throw new Error(`Unsupported operation: ${op}`);
  }
}

function getValueAtPath(obj: any, pathParts: string[]): any {
  let current = obj;
  for (const part of pathParts) {
    if (current === null || current === undefined) {
      throw new Error(`Path not found: ${pathParts.join('/')}`);
    }
    current = current[part];
  }
  return current;
}

function setValueAtPath(obj: any, pathParts: string[], value: any, allowCreate: boolean): void {
  if (pathParts.length === 0) {
    throw new Error('Cannot set root object');
  }

  let current = obj;
  for (let i = 0; i < pathParts.length - 1; i++) {
    const part = pathParts[i];
    if (!(part in current)) {
      if (allowCreate) {
        current[part] = {};
      } else {
        throw new Error(`Path not found: ${pathParts.slice(0, i + 1).join('/')}`);
      }
    }
    current = current[part];
  }

  const lastPart = pathParts[pathParts.length - 1];
  if (!allowCreate && !(lastPart in current)) {
    throw new Error(`Path not found: ${pathParts.join('/')}`);
  }
  
  current[lastPart] = value;
}

function removeValueAtPath(obj: any, pathParts: string[]): void {
  if (pathParts.length === 0) {
    throw new Error('Cannot remove root object');
  }

  let current = obj;
  for (let i = 0; i < pathParts.length - 1; i++) {
    const part = pathParts[i];
    if (!(part in current)) {
      throw new Error(`Path not found: ${pathParts.slice(0, i + 1).join('/')}`);
    }
    current = current[part];
  }

  const lastPart = pathParts[pathParts.length - 1];
  if (!(lastPart in current)) {
    throw new Error(`Path not found: ${pathParts.join('/')}`);
  }
  
  delete current[lastPart];
}

export default router;

