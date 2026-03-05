import { MongoClient, Db, Collection, Document } from 'mongodb';

let db: Db;
let client: MongoClient;

function getEnvOrThrow(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} environment variable is not set`);
  }
  return value;
}

export const initializeMongoDB = async (): Promise<void> => {
  try {
    const uri = getEnvOrThrow('MONGODB_URI');
    const dbName = getEnvOrThrow('MONGODB_DB_NAME');
    client = new MongoClient(uri);
    await client.connect();
    db = client.db(dbName);
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
  const name = collectionName || getEnvOrThrow('MONGODB_COLLECTION_NAME');
  return getDatabase().collection<T>(name);
};

export const closeConnection = async (): Promise<void> => {
  if (client) {
    await client.close();
  }
};

