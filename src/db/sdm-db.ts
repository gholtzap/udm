import { Collection } from 'mongodb';
import { getCollection } from './mongodb';
import {
  SubscriptionDataSets,
  SdmSubscription,
  SharedData,
  SharedDataId,
  GroupIdentifiers
} from '../types/nudm-sdm-types';

export interface SdmSubscriptionDocument {
  ueId: string;
  subscriptionId: string;
  subscription: SdmSubscription;
}

export interface SharedDataSubscriptionDocument {
  subscriptionId: string;
  subscription: SdmSubscription;
}

export interface GroupIdentifiersDocument {
  extGroupId?: string;
  intGroupId?: string;
  data: GroupIdentifiers;
}

let subscriptionsCollection: Collection<SubscriptionDataSets>;
let sdmSubscriptionsCollection: Collection<SdmSubscriptionDocument>;
let sharedDataCollection: Collection<SharedData>;
let sharedDataSubscriptionsCollection: Collection<SharedDataSubscriptionDocument>;
let groupIdentifiersCollection: Collection<GroupIdentifiersDocument>;

export const initializeSdmCollections = async (): Promise<void> => {
  subscriptionsCollection = getCollection<SubscriptionDataSets>('subscriptions');
  sdmSubscriptionsCollection = getCollection<SdmSubscriptionDocument>('sdm_subscriptions');
  sharedDataCollection = getCollection<SharedData>('shared_data');
  sharedDataSubscriptionsCollection = getCollection<SharedDataSubscriptionDocument>('shared_data_subscriptions');
  groupIdentifiersCollection = getCollection<GroupIdentifiersDocument>('group_identifiers');

  await subscriptionsCollection.createIndex({ supi: 1 }, { unique: true });
  await sdmSubscriptionsCollection.createIndex({ ueId: 1, subscriptionId: 1 }, { unique: true });
  await sdmSubscriptionsCollection.createIndex({ ueId: 1 });
  await sharedDataCollection.createIndex({ sharedDataId: 1 }, { unique: true });
  await sharedDataSubscriptionsCollection.createIndex({ subscriptionId: 1 }, { unique: true });
  await groupIdentifiersCollection.createIndex({ extGroupId: 1 }, { sparse: true });
  await groupIdentifiersCollection.createIndex({ intGroupId: 1 }, { sparse: true });
};

export const getSubscriptionData = async (supi: string): Promise<SubscriptionDataSets | null> => {
  return await subscriptionsCollection.findOne({ supi } as any);
};

export const setSubscriptionData = async (supi: string, data: SubscriptionDataSets): Promise<void> => {
  await subscriptionsCollection.updateOne(
    { supi } as any,
    { $set: { ...data, supi } },
    { upsert: true }
  );
};

export const getAllSubscriptionData = async (): Promise<Map<string, SubscriptionDataSets>> => {
  const docs = await subscriptionsCollection.find({}).toArray();
  const map = new Map<string, SubscriptionDataSets>();
  for (const doc of docs) {
    const supi = (doc as any).supi;
    if (supi) {
      map.set(supi, doc);
    }
  }
  return map;
};

export const getSdmSubscription = async (ueId: string, subscriptionId: string): Promise<SdmSubscription | null> => {
  const doc = await sdmSubscriptionsCollection.findOne({ ueId, subscriptionId });
  return doc?.subscription || null;
};

export const setSdmSubscription = async (ueId: string, subscriptionId: string, subscription: SdmSubscription): Promise<void> => {
  await sdmSubscriptionsCollection.updateOne(
    { ueId, subscriptionId },
    { $set: { ueId, subscriptionId, subscription } },
    { upsert: true }
  );
};

export const deleteSdmSubscription = async (ueId: string, subscriptionId: string): Promise<boolean> => {
  const result = await sdmSubscriptionsCollection.deleteOne({ ueId, subscriptionId });
  return result.deletedCount > 0;
};

export const hasSdmSubscription = async (ueId: string, subscriptionId: string): Promise<boolean> => {
  const count = await sdmSubscriptionsCollection.countDocuments({ ueId, subscriptionId }, { limit: 1 });
  return count > 0;
};

export const deleteSdmSubscriptionsForUe = async (ueId: string): Promise<void> => {
  await sdmSubscriptionsCollection.deleteMany({ ueId });
};

export const getSharedData = async (sharedDataId: SharedDataId): Promise<SharedData | null> => {
  return await sharedDataCollection.findOne({ sharedDataId } as any);
};

export const setSharedData = async (sharedDataId: SharedDataId, data: SharedData): Promise<void> => {
  await sharedDataCollection.updateOne(
    { sharedDataId } as any,
    { $set: data },
    { upsert: true }
  );
};

export const getSharedDataSubscription = async (subscriptionId: string): Promise<SdmSubscription | null> => {
  const doc = await sharedDataSubscriptionsCollection.findOne({ subscriptionId });
  return doc?.subscription || null;
};

export const setSharedDataSubscription = async (subscriptionId: string, subscription: SdmSubscription): Promise<void> => {
  await sharedDataSubscriptionsCollection.updateOne(
    { subscriptionId },
    { $set: { subscriptionId, subscription } },
    { upsert: true }
  );
};

export const deleteSharedDataSubscription = async (subscriptionId: string): Promise<boolean> => {
  const result = await sharedDataSubscriptionsCollection.deleteOne({ subscriptionId });
  return result.deletedCount > 0;
};

export const hasSharedDataSubscription = async (subscriptionId: string): Promise<boolean> => {
  const count = await sharedDataSubscriptionsCollection.countDocuments({ subscriptionId }, { limit: 1 });
  return count > 0;
};

export const getGroupIdentifiers = async (extGroupId?: string, intGroupId?: string): Promise<GroupIdentifiers | null> => {
  const query: any = {};
  if (extGroupId) {
    query.extGroupId = extGroupId;
  } else if (intGroupId) {
    query.intGroupId = intGroupId;
  } else {
    return null;
  }

  const doc = await groupIdentifiersCollection.findOne(query);
  return doc?.data || null;
};

export const setGroupIdentifiers = async (extGroupId: string | undefined, intGroupId: string | undefined, data: GroupIdentifiers): Promise<void> => {
  const query: any = {};
  if (extGroupId) {
    query.extGroupId = extGroupId;
  } else if (intGroupId) {
    query.intGroupId = intGroupId;
  } else {
    throw new Error('Either extGroupId or intGroupId must be provided');
  }

  await groupIdentifiersCollection.updateOne(
    query,
    { $set: { extGroupId, intGroupId, data } },
    { upsert: true }
  );
};
