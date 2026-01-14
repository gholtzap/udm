import { MongoClient, Db, Collection, Document } from 'mongodb';

const validateEnvironmentVariables = (): { uri: string; dbName: string; collectionName: string } => {
  const uri = process.env.MONGODB_URI;
  const dbName = process.env.MONGODB_DB_NAME;
  const collectionName = process.env.MONGODB_COLLECTION_NAME;

  if (!uri) {
    throw new Error('MONGODB_URI environment variable is not set');
  }

  if (!dbName) {
    throw new Error('MONGODB_DB_NAME environment variable is not set');
  }

  if (!collectionName) {
    throw new Error('MONGODB_COLLECTION_NAME environment variable is not set');
  }

  return { uri, dbName, collectionName };
};

const { uri: MONGODB_URI, dbName: DB_NAME, collectionName: COLLECTION_NAME } = validateEnvironmentVariables();

let db: Db;
let client: MongoClient;

export const initializeMongoDB = async (): Promise<void> => {
  try {
    client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db(DB_NAME);
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Failed to connect to MongoDB: ${error.message}`);
    }
    throw error;
  }
};

export const getDatabase = (): Db => {
  if (!db) {
    throw new Error('Database not initialized. Call initializeMongoDB first.');
  }
  return db;
};

export const getCollection = <T extends Document = Document>(collectionName?: string): Collection<T> => {
  const name = collectionName || COLLECTION_NAME;
  return getDatabase().collection<T>(name);
};

export const closeConnection = async (): Promise<void> => {
  if (client) {
    await client.close();
  }
};

