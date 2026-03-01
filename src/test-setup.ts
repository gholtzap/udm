import sinon from 'sinon';
import * as mongodb from './db/mongodb';

const mockStore: Map<string, any> = new Map();

function findOneFake(query: any) {
  if (query._id) {
    return mockStore.get(query._id) || null;
  }
  for (const [, value] of mockStore.entries()) {
    let matches = true;
    for (const [qKey, qValue] of Object.entries(query)) {
      const docValue = value[qKey];
      if (Array.isArray(docValue)) {
        if (!docValue.includes(qValue)) {
          matches = false;
          break;
        }
      } else if (docValue !== qValue) {
        matches = false;
        break;
      }
    }
    if (matches) {
      return value;
    }
  }
  return null;
}

function insertOneFake(doc: any) {
  const id = doc._id || 'mock-id';
  mockStore.set(id, { ...doc });
  return { insertedId: id };
}

function deleteOneFake(query: any) {
  if (query._id && mockStore.has(query._id)) {
    mockStore.delete(query._id);
    return { deletedCount: 1 };
  }
  return { deletedCount: 0 };
}

function updateOneFake(query: any, update: any) {
  if (query._id && mockStore.has(query._id)) {
    const existing = mockStore.get(query._id);
    if (update.$set) {
      Object.assign(existing, update.$set);
    }
    mockStore.set(query._id, existing);
    return { modifiedCount: 1 };
  }
  return { modifiedCount: 0 };
}

function findOneAndUpdateFake(query: any, update: any) {
  if (query._id && mockStore.has(query._id)) {
    const existing = mockStore.get(query._id);
    if (update.$set) {
      Object.assign(existing, update.$set);
    }
    mockStore.set(query._id, existing);
    return { value: existing };
  }
  return { value: null };
}

function replaceOneFake(query: any, replacement: any) {
  if (query._id && mockStore.has(query._id)) {
    mockStore.set(query._id, replacement);
    return { modifiedCount: 1, matchedCount: 1 };
  }
  return { modifiedCount: 0, matchedCount: 0 };
}

export const mockCollection = {
  insertOne: sinon.stub(),
  findOne: sinon.stub(),
  deleteOne: sinon.stub(),
  updateOne: sinon.stub(),
  findOneAndUpdate: sinon.stub(),
  replaceOne: sinon.stub()
};

sinon.stub(mongodb, 'getCollection').returns(mockCollection as any);

beforeEach(() => {
  mockStore.clear();
  (mockCollection.insertOne as sinon.SinonStub).reset();
  (mockCollection.insertOne as sinon.SinonStub).callsFake(insertOneFake);
  (mockCollection.findOne as sinon.SinonStub).reset();
  (mockCollection.findOne as sinon.SinonStub).callsFake(findOneFake);
  (mockCollection.deleteOne as sinon.SinonStub).reset();
  (mockCollection.deleteOne as sinon.SinonStub).callsFake(deleteOneFake);
  (mockCollection.updateOne as sinon.SinonStub).reset();
  (mockCollection.updateOne as sinon.SinonStub).callsFake(updateOneFake);
  (mockCollection.findOneAndUpdate as sinon.SinonStub).reset();
  (mockCollection.findOneAndUpdate as sinon.SinonStub).callsFake(findOneAndUpdateFake);
  (mockCollection.replaceOne as sinon.SinonStub).reset();
  (mockCollection.replaceOne as sinon.SinonStub).callsFake(replaceOneFake);
});
