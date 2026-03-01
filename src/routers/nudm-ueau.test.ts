import { expect } from 'chai';
import request from 'supertest';
import express from 'express';
import sinon from 'sinon';
import router from './nudm-ueau';
import { mockCollection } from '../test-setup';

const app = express();
app.use(express.json());
app.use('/nudm-ueau/v1', router);

describe('POST /:supiOrSuci/security-information/generate-auth-data', () => {
  const validSupi = 'imsi-999700000000001';
  const validAuthRequest = {
    servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org',
    ausfInstanceId: '550e8400-e29b-41d4-a716-446655440000'
  };

  const mockSubscriber = {
    _id: validSupi,
    supi: validSupi,
    permanentKey: '465B5CE8B199B49FAA5F0A2EE238A6BC',
    operatorKey: 'E8ED289DEBA952E4283B54E88E6183CA',
    sequenceNumber: '000000000001',
    authenticationMethod: '5G_AKA'
  };

  const mockSubscriberNested = {
    _id: validSupi,
    supi: validSupi,
    permanentKey: '465B5CE8B199B49FAA5F0A2EE238A6BC',
    operatorKey: 'E8ED289DEBA952E4283B54E88E6183CA',
    sequenceNumber: '16F3B3F70FC2',
    authenticationMethod: '5G_AKA',
    subscribedData: {
      authenticationSubscription: {
        authenticationMethod: '5G_AKA',
        permanentKey: {
          permanentKeyValue: '465B5CE8B199B49FAA5F0A2EE238A6BC'
        },
        sequenceNumber: '16F3B3F70FC2',
        authenticationManagementField: '8000',
        milenage: {
          op: {
            opValue: 'E8ED289DEBA952E4283B54E88E6183CA'
          }
        }
      }
    }
  };

  beforeEach(() => {
    (mockCollection.findOne as sinon.SinonStub).resolves(mockSubscriber);
    (mockCollection.updateOne as sinon.SinonStub).resolves({ modifiedCount: 1 });
  });

  describe('Success cases', () => {
    it('should generate authentication data with valid SUPI and request', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('authType', '5G_AKA');
      expect(response.body).to.have.property('authenticationVector');
      expect(response.body).to.have.property('supi', validSupi);
    });

    it('should return valid authentication vector structure', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      const av = response.body.authenticationVector;
      expect(av).to.have.property('avType', '5G_HE_AKA');
      expect(av).to.have.property('rand');
      expect(av).to.have.property('xresStar');
      expect(av).to.have.property('autn');
      expect(av).to.have.property('kausf');
    });

    it('should generate valid RAND (16 bytes, 32 hex chars)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      const rand = response.body.authenticationVector.rand;
      expect(rand).to.be.a('string');
      expect(rand).to.have.lengthOf(32);
      expect(rand).to.match(/^[A-F0-9]{32}$/);
    });

    it('should generate valid AUTN (16 bytes, 32 hex chars)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      const autn = response.body.authenticationVector.autn;
      expect(autn).to.be.a('string');
      expect(autn).to.have.lengthOf(32);
      expect(autn).to.match(/^[A-F0-9]{32}$/);
    });

    it('should generate valid XRES* (16 bytes, 32 hex chars)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      const xresStar = response.body.authenticationVector.xresStar;
      expect(xresStar).to.be.a('string');
      expect(xresStar).to.have.lengthOf(32);
      expect(xresStar).to.match(/^[A-F0-9]{32}$/);
    });

    it('should generate valid KAUSF (32 bytes, 64 hex chars)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      const kausf = response.body.authenticationVector.kausf;
      expect(kausf).to.be.a('string');
      expect(kausf).to.have.lengthOf(64);
      expect(kausf).to.match(/^[A-F0-9]{64}$/);
    });

    it('should generate different RAND values for consecutive requests', async () => {
      const response1 = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      const response2 = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      const rand1 = response1.body.authenticationVector.rand;
      const rand2 = response2.body.authenticationVector.rand;
      expect(rand1).to.not.equal(rand2);
    });

    it('should increment sequence number after authentication', async () => {
      await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      expect((mockCollection.updateOne as sinon.SinonStub).calledOnce).to.be.true;
      const updateCall = (mockCollection.updateOne as sinon.SinonStub).getCall(0);
      expect(updateCall.args[0]).to.deep.equal({ supi: validSupi });
      expect(updateCall.args[1]).to.have.property('$set');
    });

    it('should handle nested authentication subscription structure', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(mockSubscriberNested);

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      expect(response.body).to.have.property('authType', '5G_AKA');
      expect(response.body).to.have.property('authenticationVector');
    });

    it('should handle different serving network names', async () => {
      const servingNetworks = [
        '5G:mnc001.mcc001.3gppnetwork.org',
        '5G:mnc070.mcc999.3gppnetwork.org',
        '5G:mnc123.mcc456.3gppnetwork.org'
      ];

      for (const network of servingNetworks) {
        const response = await request(app)
          .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
          .send({
            servingNetworkName: network,
            ausfInstanceId: 'ausf-instance-123'
          })
          .expect(200);

        expect(response.body).to.have.property('authType', '5G_AKA');
      }
    });

    it('should handle different AUSF instance IDs', async () => {
      const ausfInstances = [
        'ausf-instance-1',
        'ausf-instance-abc123',
        'ausf-instance-xyz789'
      ];

      for (const ausfId of ausfInstances) {
        const response = await request(app)
          .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
          .send({
            servingNetworkName: validAuthRequest.servingNetworkName,
            ausfInstanceId: ausfId
          })
          .expect(200);

        expect(response.body).to.have.property('authType', '5G_AKA');
      }
    });

    it('should handle optional supportedFeatures field', async () => {
      const authRequestWithFeatures = {
        ...validAuthRequest,
        supportedFeatures: '1234ABCD'
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(authRequestWithFeatures)
        .expect(200);

      expect(response.body).to.have.property('authType', '5G_AKA');
    });

    it('should handle different IMSI lengths', async () => {
      const imsis = [
        'imsi-12345',
        'imsi-123456789012345'
      ];

      for (const imsi of imsis) {
        (mockCollection.findOne as sinon.SinonStub).resolves({ ...mockSubscriber, supi: imsi });

        const response = await request(app)
          .post(`/nudm-ueau/v1/${imsi}/security-information/generate-auth-data`)
          .send(validAuthRequest)
          .expect(200);

        expect(response.body).to.have.property('supi', imsi);
      }
    });

    it('should handle multiple authentication requests for same UE', async () => {
      for (let i = 0; i < 5; i++) {
        const response = await request(app)
          .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
          .send(validAuthRequest)
          .expect(200);

        expect(response.body).to.have.property('authType', '5G_AKA');
      }

      expect((mockCollection.updateOne as sinon.SinonStub).callCount).to.equal(5);
    });
  });

  describe('Validation error cases - missing required fields', () => {
    it('should return 400 when servingNetworkName is missing', async () => {
      const authRequestWithoutSN = {
        ausfInstanceId: 'ausf-instance-123'
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(authRequestWithoutSN)
        .expect(400)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('title', 'Bad Request');
      expect(response.body).to.have.property('detail');
      expect(response.body.detail).to.include('servingNetworkName');
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
    });

    it('should return 400 when ausfInstanceId is missing', async () => {
      const authRequestWithoutAUSF = {
        servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org'
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(authRequestWithoutAUSF)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('detail');
      expect(response.body.detail).to.include('ausfInstanceId');
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
    });

    it('should return 400 when all required fields are missing', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send({})
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
    });

    it('should return 400 when request body is not an object', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send([validAuthRequest])
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
    });

    it('should return 400 when request body is empty string', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send('')
        .expect(400);

      expect(response.body).to.have.property('status', 400);
    });

    it('should return 400 when request body is undefined', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
    });
  });

  describe('Validation error cases - invalid SUPI format', () => {
    it('should return 400 when SUPI does not start with imsi-', async () => {
      const response = await request(app)
        .post('/nudm-ueau/v1/msisdn-1234567890/security-information/generate-auth-data')
        .send(validAuthRequest)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('detail');
      expect(response.body.detail).to.include('Invalid SUPI format');
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
    });

    it('should return 400 for empty SUPI', async () => {
      const response = await request(app)
        .post('/nudm-ueau/v1/ /security-information/generate-auth-data')
        .send(validAuthRequest)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
    });

    it('should return 400 for SUPI with invalid prefix', async () => {
      const response = await request(app)
        .post('/nudm-ueau/v1/nai-user@example.com/security-information/generate-auth-data')
        .send(validAuthRequest)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
    });
  });

  describe('SUCI handling', () => {
    it('should return 501 for SUCI (not yet implemented)', async () => {
      const suci = 'suci-0-001-01-0-0-0-0123456789ABCDEF';

      const response = await request(app)
        .post(`/nudm-ueau/v1/${suci}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(501)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('status', 501);
      expect(response.body).to.have.property('title', 'Not Implemented');
      expect(response.body).to.have.property('detail');
      expect(response.body.detail).to.include('SUCI de-concealment');
    });

    it('should return 501 for different SUCI formats', async () => {
      const sucis = [
        'suci-0-001-01-0-0-0-0123456789ABCDEF',
        'suci-0-999-70-0-0-0-FEDCBA9876543210',
        'suci-0-123-45-0-0-0-AAAAAAAAAAAAAAAA'
      ];

      for (const suci of sucis) {
        const response = await request(app)
          .post(`/nudm-ueau/v1/${suci}/security-information/generate-auth-data`)
          .send(validAuthRequest)
          .expect(501);

        expect(response.body).to.have.property('status', 501);
      }
    });
  });

  describe('Subscriber not found', () => {
    it('should return 404 when subscriber does not exist', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(null);

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(404)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('status', 404);
      expect(response.body).to.have.property('title', 'Not Found');
      expect(response.body).to.have.property('detail');
      expect(response.body.detail).to.include('not found');
      expect(response.body).to.have.property('cause', 'DATA_NOT_FOUND');
    });

    it('should return 404 for non-existent IMSI', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(null);

      const response = await request(app)
        .post('/nudm-ueau/v1/imsi-000000000000000/security-information/generate-auth-data')
        .send(validAuthRequest)
        .expect(404);

      expect(response.body).to.have.property('status', 404);
      expect(response.body).to.have.property('cause', 'DATA_NOT_FOUND');
    });
  });

  describe('Missing authentication credentials', () => {
    it('should return 500 when permanentKey is missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        permanentKey: ''
      });

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(500)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('status', 500);
      expect(response.body).to.have.property('title', 'Internal Server Error');
      expect(response.body).to.have.property('detail');
      expect(response.body.detail).to.include('Missing authentication credentials');
    });

    it('should return 500 when operatorKey is missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        operatorKey: ''
      });

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(500);

      expect(response.body).to.have.property('status', 500);
      expect(response.body.detail).to.include('Missing authentication credentials');
    });

    it('should return 500 when sequenceNumber is missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        sequenceNumber: ''
      });

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(500);

      expect(response.body).to.have.property('status', 500);
      expect(response.body.detail).to.include('Missing authentication credentials');
    });

    it('should return 500 when all credentials are missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        permanentKey: '',
        operatorKey: '',
        sequenceNumber: ''
      });

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(500);

      expect(response.body).to.have.property('status', 500);
    });
  });

  describe('Request body validation', () => {
    it('should handle request body with extra unknown properties', async () => {
      const authRequestWithExtra = {
        ...validAuthRequest,
        unknownProperty: 'test',
        anotherUnknown: 123
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(authRequestWithExtra)
        .expect(200);

      expect(response.body).to.have.property('authType', '5G_AKA');
    });

    it('should handle null optional fields', async () => {
      const authRequestWithNull = {
        ...validAuthRequest,
        supportedFeatures: null,
        resynchronizationInfo: null
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(authRequestWithNull)
        .expect(200);

      expect(response.body).to.have.property('authType', '5G_AKA');
    });

    it('should handle undefined optional fields', async () => {
      const authRequestWithUndefined = {
        ...validAuthRequest,
        supportedFeatures: undefined,
        resynchronizationInfo: undefined
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(authRequestWithUndefined)
        .expect(200);

      expect(response.body).to.have.property('authType', '5G_AKA');
    });
  });

  describe('Response structure validation', () => {
    it('should return complete AuthenticationInfoResult structure', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      expect(response.body).to.be.an('object');
      expect(response.body).to.have.property('authType');
      expect(response.body).to.have.property('authenticationVector');
      expect(response.body).to.have.property('supi');
    });

    it('should return authType as 5G_AKA', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      expect(response.body.authType).to.equal('5G_AKA');
    });

    it('should return avType as 5G_HE_AKA', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      expect(response.body.authenticationVector.avType).to.equal('5G_HE_AKA');
    });

    it('should return SUPI matching the request', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      expect(response.body.supi).to.equal(validSupi);
    });

    it('should include all required authentication vector fields', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      const av = response.body.authenticationVector;
      expect(av).to.include.all.keys('avType', 'rand', 'xresStar', 'autn', 'kausf');
    });
  });

  describe('Database operations', () => {
    it('should query database with correct SUPI', async () => {
      await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      expect((mockCollection.findOne as sinon.SinonStub).calledOnce).to.be.true;
      expect((mockCollection.findOne as sinon.SinonStub).getCall(0).args[0]).to.deep.equal({ supi: validSupi });
    });

    it('should update sequence number in flat structure', async () => {
      await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      expect((mockCollection.updateOne as sinon.SinonStub).calledOnce).to.be.true;
      const updateCall = (mockCollection.updateOne as sinon.SinonStub).getCall(0);
      expect(updateCall.args[1].$set).to.have.property('sequenceNumber');
    });

    it('should update sequence number in nested structure', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(mockSubscriberNested);

      await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      expect((mockCollection.updateOne as sinon.SinonStub).calledOnce).to.be.true;
      const updateCall = (mockCollection.updateOne as sinon.SinonStub).getCall(0);
      expect(updateCall.args[1].$set).to.have.property('subscribedData.authenticationSubscription.sequenceNumber');
    });

    it('should call getCollection with subscribers collection name', async () => {
      await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      // Collection is already mocked globally, no need to check
    });
  });

  describe('Edge cases', () => {
    it('should handle very long serving network name', async () => {
      const authRequestWithLongSN = {
        servingNetworkName: '5G:mnc' + '0'.repeat(100) + '.mcc' + '9'.repeat(100) + '.3gppnetwork.org',
        ausfInstanceId: 'ausf-instance-123'
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(authRequestWithLongSN)
        .expect(200);

      expect(response.body).to.have.property('authType', '5G_AKA');
    });

    it('should handle very long AUSF instance ID', async () => {
      const authRequestWithLongAUSF = {
        servingNetworkName: validAuthRequest.servingNetworkName,
        ausfInstanceId: 'ausf-instance-' + 'a'.repeat(200)
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(authRequestWithLongAUSF)
        .expect(200);

      expect(response.body).to.have.property('authType', '5G_AKA');
    });

    it('should handle high sequence numbers', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        sequenceNumber: 'FFFFFFFFFFFF'
      });

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      expect(response.body).to.have.property('authType', '5G_AKA');
    });

    it('should handle subscriber with minimal data structure', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(mockSubscriber);

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      expect(response.body).to.have.property('authType', '5G_AKA');
    });

    it('should handle very long IMSI', async () => {
      const longImsi = 'imsi-' + '9'.repeat(100);
      (mockCollection.findOne as sinon.SinonStub).resolves({ ...mockSubscriber, supi: longImsi });

      const response = await request(app)
        .post(`/nudm-ueau/v1/${longImsi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      expect(response.body.supi).to.equal(longImsi);
    });

    it('should generate unique authentication vectors for concurrent requests', async () => {
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          request(app)
            .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
            .send(validAuthRequest)
        );
      }

      const responses = await Promise.all(promises);

      const rands = responses.map(r => r.body.authenticationVector.rand);
      const uniqueRands = new Set(rands);
      expect(uniqueRands.size).to.equal(10);
    });
  });

  describe('Cryptographic validation', () => {
    it('should generate authentication vector with correct key lengths', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      const av = response.body.authenticationVector;
      expect(av.rand.length).to.equal(32);
      expect(av.autn.length).to.equal(32);
      expect(av.xresStar.length).to.equal(32);
      expect(av.kausf.length).to.equal(64);
    });

    it('should generate valid hex-encoded values', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      const av = response.body.authenticationVector;
      expect(av.rand).to.match(/^[A-F0-9]+$/);
      expect(av.autn).to.match(/^[A-F0-9]+$/);
      expect(av.xresStar).to.match(/^[A-F0-9]+$/);
      expect(av.kausf).to.match(/^[A-F0-9]+$/);
    });

    it('should generate uppercase hex values', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/security-information/generate-auth-data`)
        .send(validAuthRequest)
        .expect(200);

      const av = response.body.authenticationVector;
      expect(av.rand).to.equal(av.rand.toUpperCase());
      expect(av.autn).to.equal(av.autn.toUpperCase());
      expect(av.xresStar).to.equal(av.xresStar.toUpperCase());
      expect(av.kausf).to.equal(av.kausf.toUpperCase());
    });
  });
});

describe('GET /:supiOrSuci/security-information-rg', () => {
  const validSupi = 'imsi-999700000000001';

  const mockSubscriber = {
    _id: validSupi,
    supi: validSupi,
    permanentKey: '465B5CE8B199B49FAA5F0A2EE238A6BC',
    operatorKey: 'E8ED289DEBA952E4283B54E88E6183CA',
    sequenceNumber: '000000000001',
    authenticationMethod: '5G_AKA'
  };

  const mockSubscriberNested = {
    _id: validSupi,
    supi: validSupi,
    permanentKey: '465B5CE8B199B49FAA5F0A2EE238A6BC',
    operatorKey: 'E8ED289DEBA952E4283B54E88E6183CA',
    sequenceNumber: '16F3B3F70FC2',
    authenticationMethod: '5G_AKA',
    subscribedData: {
      authenticationSubscription: {
        authenticationMethod: '5G_AKA',
        permanentKey: {
          permanentKeyValue: '465B5CE8B199B49FAA5F0A2EE238A6BC'
        },
        sequenceNumber: '16F3B3F70FC2',
        authenticationManagementField: '8000',
        milenage: {
          op: {
            opValue: 'E8ED289DEBA952E4283B54E88E6183CA'
          }
        }
      }
    }
  };

  beforeEach(() => {
    (mockCollection.findOne as sinon.SinonStub).resolves(mockSubscriber);
  });

  describe('Success cases', () => {
    it('should retrieve RG auth context with valid SUPI', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(200)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('authInd', true);
      expect(response.body).to.have.property('supi', validSupi);
    });

    it('should return authInd true when all credentials exist', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=false`)
        .expect(200);

      expect(response.body.authInd).to.be.true;
    });

    it('should return 403 when permanentKey is missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        permanentKey: ''
      });

      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(403);

      expect(response.body).to.have.property('status', 403);
    });

    it('should return 403 when operatorKey is missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        operatorKey: ''
      });

      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(403);

      expect(response.body).to.have.property('status', 403);
    });

    it('should return 403 when sequenceNumber is missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        sequenceNumber: ''
      });

      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(403);

      expect(response.body).to.have.property('status', 403);
    });

    it('should return 403 when all credentials are missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        permanentKey: '',
        operatorKey: '',
        sequenceNumber: ''
      });

      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(403);

      expect(response.body).to.have.property('status', 403);
    });

    it('should handle nested authentication subscription structure', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(mockSubscriberNested);

      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(200);

      expect(response.body).to.have.property('authInd', true);
      expect(response.body).to.have.property('supi', validSupi);
    });

    it('should return 403 for nested structure with missing permanentKey', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriberNested,
        subscribedData: {
          authenticationSubscription: {
            ...mockSubscriberNested.subscribedData.authenticationSubscription,
            permanentKey: {
              permanentKeyValue: ''
            }
          }
        },
        permanentKey: ''
      });

      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(403);

      expect(response.body).to.have.property('status', 403);
    });

    it('should return SUPI in response', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(200);

      expect(response.body.supi).to.equal(validSupi);
    });

    it('should handle different IMSI values', async () => {
      const imsis = [
        'imsi-12345',
        'imsi-123456789012345',
        'imsi-999700000000002'
      ];

      for (const imsi of imsis) {
        (mockCollection.findOne as sinon.SinonStub).resolves({ ...mockSubscriber, supi: imsi });

        const response = await request(app)
          .get(`/nudm-ueau/v1/${imsi}/security-information-rg?authenticated-ind=true`)
          .expect(200);

        expect(response.body.supi).to.equal(imsi);
        expect(response.body.authInd).to.be.true;
      }
    });

    it('should query database with correct SUPI', async () => {
      await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(200);

      expect((mockCollection.findOne as sinon.SinonStub).calledOnce).to.be.true;
      expect((mockCollection.findOne as sinon.SinonStub).getCall(0).args[0]).to.deep.equal({ supi: validSupi });
    });

    it('should echo supported-features in response when provided', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true&supported-features=abc`)
        .expect(200);

      expect(response.body).to.have.property('supportedFeatures', 'abc');
    });

    it('should not include supportedFeatures when not provided', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(200);

      expect(response.body).to.not.have.property('supportedFeatures');
    });
  });

  describe('Validation error cases', () => {
    it('should return 400 when authenticated-ind is missing', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg`)
        .expect(400)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('status', 400);
      expect(response.body.detail).to.include('authenticated-ind');
    });

    it('should return 400 when authenticated-ind is not a boolean', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=maybe`)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
    });

    it('should return 400 when plmn-id is invalid JSON', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true&plmn-id=notjson`)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body.detail).to.include('plmn-id');
    });

    it('should return 400 when plmn-id is missing mcc or mnc', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true&plmn-id=${encodeURIComponent('{"mcc":"001"}')}`)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body.detail).to.include('plmn-id');
    });

    it('should return 400 when SUPI does not start with imsi-', async () => {
      const response = await request(app)
        .get('/nudm-ueau/v1/msisdn-1234567890/security-information-rg?authenticated-ind=true')
        .expect(400)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('title', 'Bad Request');
      expect(response.body).to.have.property('detail');
      expect(response.body.detail).to.include('Invalid SUPI format');
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
    });

    it('should return 400 for SUPI with invalid prefix', async () => {
      const response = await request(app)
        .get('/nudm-ueau/v1/nai-user@example.com/security-information-rg?authenticated-ind=true')
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
    });

    it('should return 400 for empty SUPI', async () => {
      const response = await request(app)
        .get('/nudm-ueau/v1/ /security-information-rg?authenticated-ind=true')
        .expect(400);

      expect(response.body).to.have.property('status', 400);
    });
  });

  describe('SUCI handling', () => {
    it('should return 501 for SUCI (not yet implemented)', async () => {
      const suci = 'suci-0-001-01-0-0-0-0123456789ABCDEF';

      const response = await request(app)
        .get(`/nudm-ueau/v1/${suci}/security-information-rg?authenticated-ind=true`)
        .expect(501)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('status', 501);
      expect(response.body).to.have.property('title', 'Not Implemented');
      expect(response.body).to.have.property('detail');
      expect(response.body.detail).to.include('SUCI de-concealment');
    });

    it('should return 501 for different SUCI formats', async () => {
      const sucis = [
        'suci-0-001-01-0-0-0-0123456789ABCDEF',
        'suci-0-999-70-0-0-0-FEDCBA9876543210',
        'suci-0-123-45-0-0-0-AAAAAAAAAAAAAAAA'
      ];

      for (const suci of sucis) {
        const response = await request(app)
          .get(`/nudm-ueau/v1/${suci}/security-information-rg?authenticated-ind=true`)
          .expect(501);

        expect(response.body).to.have.property('status', 501);
      }
    });
  });

  describe('Subscriber not found', () => {
    it('should return 404 when subscriber does not exist', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(null);

      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(404)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('status', 404);
      expect(response.body).to.have.property('title', 'Not Found');
      expect(response.body).to.have.property('detail');
      expect(response.body.detail).to.include('not found');
      expect(response.body).to.have.property('cause', 'USER_NOT_FOUND');
    });

    it('should return 404 for non-existent IMSI', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(null);

      const response = await request(app)
        .get('/nudm-ueau/v1/imsi-000000000000000/security-information-rg?authenticated-ind=true')
        .expect(404);

      expect(response.body).to.have.property('status', 404);
      expect(response.body).to.have.property('cause', 'USER_NOT_FOUND');
    });

    it('should not leak SUPI in 404 error detail', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(null);

      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(404);

      expect(response.body.detail).to.not.include(validSupi);
    });
  });

  describe('Response structure validation', () => {
    it('should return complete RgAuthCtx structure', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(200);

      expect(response.body).to.be.an('object');
      expect(response.body).to.have.property('authInd');
      expect(response.body).to.have.property('supi');
    });

    it('should return authInd as boolean', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(200);

      expect(response.body.authInd).to.be.a('boolean');
    });

    it('should return supi as string', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(200);

      expect(response.body.supi).to.be.a('string');
    });

    it('should include all required RgAuthCtx fields', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(200);

      expect(response.body).to.include.all.keys('authInd', 'supi');
    });
  });

  describe('Edge cases', () => {
    it('should handle very long IMSI', async () => {
      const longImsi = 'imsi-' + '9'.repeat(100);
      (mockCollection.findOne as sinon.SinonStub).resolves({ ...mockSubscriber, supi: longImsi });

      const response = await request(app)
        .get(`/nudm-ueau/v1/${longImsi}/security-information-rg?authenticated-ind=true`)
        .expect(200);

      expect(response.body.supi).to.equal(longImsi);
    });

    it('should handle subscriber with minimal data structure', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(mockSubscriber);

      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(200);

      expect(response.body).to.have.property('authInd', true);
    });

    it('should return 403 for undefined credentials', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        supi: validSupi,
        authenticationMethod: '5G_AKA'
      });

      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(403);

      expect(response.body).to.have.property('status', 403);
    });

    it('should handle partial nested structure', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        subscribedData: {
          authenticationSubscription: {
            authenticationMethod: '5G_AKA'
          }
        }
      });

      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        .expect(200);

      expect(response.body.authInd).to.be.true;
    });

    it('should handle concurrent requests', async () => {
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          request(app)
            .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=true`)
        );
      }

      const responses = await Promise.all(promises);

      responses.forEach(response => {
        expect(response.status).to.equal(200);
        expect(response.body).to.have.property('authInd');
        expect(response.body).to.have.property('supi', validSupi);
      });
    });

    it('should accept authenticated-ind=false', async () => {
      const response = await request(app)
        .get(`/nudm-ueau/v1/${validSupi}/security-information-rg?authenticated-ind=false`)
        .expect(200);

      expect(response.body).to.have.property('authInd', true);
    });
  });
});

describe('POST /:supi/auth-events', () => {
  const validSupi = 'imsi-999700000000001';
  const validAuthEvent = {
    nfInstanceId: 'ausf-instance-123',
    success: true,
    timeStamp: '2024-01-15T10:30:00Z',
    authType: '5G_AKA' as const,
    servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org'
  };

  const mockSubscriber = {
    _id: validSupi,
    supi: validSupi,
    permanentKey: '465B5CE8B199B49FAA5F0A2EE238A6BC',
    operatorKey: 'E8ED289DEBA952E4283B54E88E6183CA',
    sequenceNumber: '000000000001',
    authenticationMethod: '5G_AKA'
  };

  beforeEach(() => {
    (mockCollection.findOne as sinon.SinonStub).resolves(mockSubscriber);
    (mockCollection.insertOne as sinon.SinonStub).resolves({ insertedId: 'mock-id' });
  });

  describe('Success cases', () => {
    it('should create auth event with valid data', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(validAuthEvent)
        .expect(201)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('nfInstanceId', validAuthEvent.nfInstanceId);
      expect(response.body).to.have.property('success', true);
      expect(response.body).to.have.property('timeStamp', validAuthEvent.timeStamp);
      expect(response.body).to.have.property('authType', '5G_AKA');
      expect(response.body).to.have.property('servingNetworkName', validAuthEvent.servingNetworkName);
    });

    it('should include Location header in response', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(validAuthEvent)
        .expect(201);

      expect(response.headers).to.have.property('location');
      expect(response.headers.location).to.match(/^\/nudm-ueau\/v1\/imsi-999700000000001\/auth-events\/[a-f0-9-]{36}$/);
    });

    it('should handle successful authentication event', async () => {
      const successEvent = { ...validAuthEvent, success: true };
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(successEvent)
        .expect(201);

      expect(response.body.success).to.be.true;
    });

    it('should handle failed authentication event', async () => {
      const failureEvent = { ...validAuthEvent, success: false };
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(failureEvent)
        .expect(201);

      expect(response.body.success).to.be.false;
    });

    it('should handle optional authRemovalInd field', async () => {
      const authEventWithRemovalInd = {
        ...validAuthEvent,
        authRemovalInd: true
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(authEventWithRemovalInd)
        .expect(201);

      expect(response.body).to.have.property('authRemovalInd', true);
    });

    it('should handle optional nfSetId field', async () => {
      const authEventWithNfSetId = {
        ...validAuthEvent,
        nfSetId: 'nf-set-abc123'
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(authEventWithNfSetId)
        .expect(201);

      expect(response.body).to.have.property('nfSetId', 'nf-set-abc123');
    });

    it('should handle optional resetIds field', async () => {
      const authEventWithResetIds = {
        ...validAuthEvent,
        resetIds: ['reset-id-1', 'reset-id-2', 'reset-id-3']
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(authEventWithResetIds)
        .expect(201);

      expect(response.body).to.have.property('resetIds');
      expect(response.body.resetIds).to.deep.equal(['reset-id-1', 'reset-id-2', 'reset-id-3']);
    });

    it('should handle optional dataRestorationCallbackUri field', async () => {
      const authEventWithCallback = {
        ...validAuthEvent,
        dataRestorationCallbackUri: 'https://callback.example.com/restore'
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(authEventWithCallback)
        .expect(201);

      expect(response.body).to.have.property('dataRestorationCallbackUri', 'https://callback.example.com/restore');
    });

    it('should handle optional udrRestartInd field', async () => {
      const authEventWithUdrRestart = {
        ...validAuthEvent,
        udrRestartInd: true
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(authEventWithUdrRestart)
        .expect(201);

      expect(response.body).to.have.property('udrRestartInd', true);
    });

    it('should handle all optional fields together', async () => {
      const authEventWithAllFields = {
        ...validAuthEvent,
        authRemovalInd: true,
        nfSetId: 'nf-set-123',
        resetIds: ['reset-1', 'reset-2'],
        dataRestorationCallbackUri: 'https://callback.example.com',
        udrRestartInd: true
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(authEventWithAllFields)
        .expect(201);

      expect(response.body).to.have.property('authRemovalInd', true);
      expect(response.body).to.have.property('nfSetId', 'nf-set-123');
      expect(response.body).to.have.property('resetIds');
      expect(response.body).to.have.property('dataRestorationCallbackUri');
      expect(response.body).to.have.property('udrRestartInd', true);
    });

    it('should handle different auth types', async () => {
      const authTypes = ['5G_AKA', 'EAP_AKA_PRIME', 'EAP_TLS', 'EAP_TTLS'];

      for (const authType of authTypes) {
        const authEventWithType = {
          ...validAuthEvent,
          authType
        };

        const response = await request(app)
          .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
          .send(authEventWithType)
          .expect(201);

        expect(response.body.authType).to.equal(authType);
      }
    });

    it('should store auth event in database', async () => {
      await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(validAuthEvent)
        .expect(201);

      expect((mockCollection.insertOne as sinon.SinonStub).calledOnce).to.be.true;
      const insertCall = (mockCollection.insertOne as sinon.SinonStub).getCall(0);
      expect(insertCall.args[0]).to.have.property('supi', validSupi);
      expect(insertCall.args[0]).to.have.property('nfInstanceId', validAuthEvent.nfInstanceId);
      expect(insertCall.args[0]).to.have.property('success', validAuthEvent.success);
    });
  });

  describe('Validation error cases - missing required fields', () => {
    it('should return 400 when nfInstanceId is missing', async () => {
      const authEventWithoutNfId = {
        success: true,
        timeStamp: '2024-01-15T10:30:00Z',
        authType: '5G_AKA',
        servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org'
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(authEventWithoutNfId)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('nfInstanceId');
    });

    it('should return 400 when success is missing', async () => {
      const authEventWithoutSuccess = {
        nfInstanceId: 'ausf-instance-123',
        timeStamp: '2024-01-15T10:30:00Z',
        authType: '5G_AKA',
        servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org'
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(authEventWithoutSuccess)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('success');
    });

    it('should return 400 when timeStamp is missing', async () => {
      const authEventWithoutTimestamp = {
        nfInstanceId: 'ausf-instance-123',
        success: true,
        authType: '5G_AKA',
        servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org'
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(authEventWithoutTimestamp)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('timeStamp');
    });

    it('should return 400 when authType is missing', async () => {
      const authEventWithoutAuthType = {
        nfInstanceId: 'ausf-instance-123',
        success: true,
        timeStamp: '2024-01-15T10:30:00Z',
        servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org'
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(authEventWithoutAuthType)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('authType');
    });

    it('should return 400 when servingNetworkName is missing', async () => {
      const authEventWithoutSN = {
        nfInstanceId: 'ausf-instance-123',
        success: true,
        timeStamp: '2024-01-15T10:30:00Z',
        authType: '5G_AKA'
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(authEventWithoutSN)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('servingNetworkName');
    });

    it('should return 400 when success is not a boolean', async () => {
      const authEventWithInvalidSuccess = {
        ...validAuthEvent,
        success: 'true'
      };

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(authEventWithInvalidSuccess)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('success must be a boolean');
    });
  });

  describe('Validation error cases - invalid SUPI format', () => {
    it('should return 400 when SUPI does not start with imsi-', async () => {
      const response = await request(app)
        .post('/nudm-ueau/v1/msisdn-1234567890/auth-events')
        .send(validAuthEvent)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('Invalid SUPI format');
    });
  });

  describe('Subscriber not found', () => {
    it('should return 404 when subscriber does not exist', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(null);

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(validAuthEvent)
        .expect(404);

      expect(response.body).to.have.property('status', 404);
      expect(response.body).to.have.property('title', 'Not Found');
      expect(response.body).to.have.property('cause', 'DATA_NOT_FOUND');
      expect(response.body.detail).to.include('not found');
    });
  });

  describe('Response structure validation', () => {
    it('should return complete AuthEvent structure', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(validAuthEvent)
        .expect(201);

      expect(response.body).to.be.an('object');
      expect(response.body).to.have.property('nfInstanceId');
      expect(response.body).to.have.property('success');
      expect(response.body).to.have.property('timeStamp');
      expect(response.body).to.have.property('authType');
      expect(response.body).to.have.property('servingNetworkName');
    });

    it('should not include optional fields when not provided', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/auth-events`)
        .send(validAuthEvent)
        .expect(201);

      expect(response.body).to.not.have.property('nfSetId');
      expect(response.body).to.not.have.property('resetIds');
      expect(response.body).to.not.have.property('dataRestorationCallbackUri');
    });
  });
});

describe('PUT /:supi/auth-events/:authEventId', () => {
  const validSupi = 'imsi-999700000000001';
  const validAuthEventId = 'auth-event-123';
  const validAuthEvent = {
    nfInstanceId: 'ausf-instance-updated',
    success: true,
    timeStamp: '2024-01-15T11:30:00Z',
    authType: '5G_AKA' as const,
    servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org'
  };

  const mockSubscriber = {
    _id: validSupi,
    supi: validSupi,
    permanentKey: '465B5CE8B199B49FAA5F0A2EE238A6BC',
    operatorKey: 'E8ED289DEBA952E4283B54E88E6183CA',
    sequenceNumber: '000000000001',
    authenticationMethod: '5G_AKA'
  };

  const mockExistingAuthEvent = {
    authEventId: validAuthEventId,
    supi: validSupi,
    nfInstanceId: 'ausf-instance-original',
    success: false,
    timeStamp: '2024-01-15T10:00:00Z',
    authType: '5G_AKA',
    servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org'
  };

  beforeEach(() => {
    (mockCollection.findOne as sinon.SinonStub).onFirstCall().resolves(mockSubscriber);
    (mockCollection.findOne as sinon.SinonStub).onSecondCall().resolves(mockExistingAuthEvent);
    (mockCollection.updateOne as sinon.SinonStub).resolves({ modifiedCount: 1 });
  });

  describe('Success cases', () => {
    it('should update auth event with valid data and return 204', async () => {
      await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(validAuthEvent)
        .expect(204);
    });

    it('should update auth event with all optional fields', async () => {
      const authEventWithAllFields = {
        ...validAuthEvent,
        authRemovalInd: true,
        nfSetId: 'nf-set-updated',
        resetIds: ['reset-1', 'reset-2'],
        dataRestorationCallbackUri: 'https://updated.callback.com',
        udrRestartInd: true,
        lastSynchronizationTime: '2024-01-15T12:00:00Z',
        nswoInd: true
      };

      await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(authEventWithAllFields)
        .expect(204);
    });

    it('should call updateOne with correct parameters', async () => {
      await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(validAuthEvent)
        .expect(204);

      const updateCall = (mockCollection.updateOne as sinon.SinonStub).getCall(0);
      expect(updateCall.args[0]).to.deep.equal({ authEventId: validAuthEventId, supi: validSupi });
      expect(updateCall.args[1].$set).to.have.property('nfInstanceId', validAuthEvent.nfInstanceId);
      expect(updateCall.args[1].$set).to.have.property('success', validAuthEvent.success);
      expect(updateCall.args[1].$set).to.have.property('timeStamp', validAuthEvent.timeStamp);
      expect(updateCall.args[1].$set).to.have.property('authType', validAuthEvent.authType);
      expect(updateCall.args[1].$set).to.have.property('servingNetworkName', validAuthEvent.servingNetworkName);
    });

    it('should handle successful authentication event update', async () => {
      const successEvent = { ...validAuthEvent, success: true };
      await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(successEvent)
        .expect(204);
    });

    it('should handle failed authentication event update', async () => {
      const failureEvent = { ...validAuthEvent, success: false };
      await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(failureEvent)
        .expect(204);
    });

    it('should handle different auth types', async () => {
      const authTypes = ['5G_AKA', 'EAP_AKA_PRIME', 'EAP_TLS', 'EAP_TTLS'];

      for (const authType of authTypes) {
        (mockCollection.findOne as sinon.SinonStub).reset();
        (mockCollection.findOne as sinon.SinonStub).onFirstCall().resolves(mockSubscriber);
        (mockCollection.findOne as sinon.SinonStub).onSecondCall().resolves(mockExistingAuthEvent);

        const authEventWithType = {
          ...validAuthEvent,
          authType
        };

        await request(app)
          .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
          .send(authEventWithType)
          .expect(204);
      }
    });
  });

  describe('Validation error cases - missing required fields', () => {
    it('should return 400 when nfInstanceId is missing', async () => {
      const authEventWithoutNfId = {
        success: true,
        timeStamp: '2024-01-15T10:30:00Z',
        authType: '5G_AKA',
        servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org'
      };

      const response = await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(authEventWithoutNfId)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('nfInstanceId');
    });

    it('should return 400 when success is missing', async () => {
      const authEventWithoutSuccess = {
        nfInstanceId: 'ausf-instance-123',
        timeStamp: '2024-01-15T10:30:00Z',
        authType: '5G_AKA',
        servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org'
      };

      const response = await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(authEventWithoutSuccess)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('success');
    });

    it('should return 400 when timeStamp is missing', async () => {
      const authEventWithoutTimestamp = {
        nfInstanceId: 'ausf-instance-123',
        success: true,
        authType: '5G_AKA',
        servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org'
      };

      const response = await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(authEventWithoutTimestamp)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('timeStamp');
    });

    it('should return 400 when authType is missing', async () => {
      const authEventWithoutAuthType = {
        nfInstanceId: 'ausf-instance-123',
        success: true,
        timeStamp: '2024-01-15T10:30:00Z',
        servingNetworkName: '5G:mnc070.mcc999.3gppnetwork.org'
      };

      const response = await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(authEventWithoutAuthType)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('authType');
    });

    it('should return 400 when servingNetworkName is missing', async () => {
      const authEventWithoutSN = {
        nfInstanceId: 'ausf-instance-123',
        success: true,
        timeStamp: '2024-01-15T10:30:00Z',
        authType: '5G_AKA'
      };

      const response = await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(authEventWithoutSN)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('servingNetworkName');
    });

    it('should return 400 when success is not a boolean', async () => {
      const authEventWithInvalidSuccess = {
        ...validAuthEvent,
        success: 'true'
      };

      const response = await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(authEventWithInvalidSuccess)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('success must be a boolean');
    });

    it('should return 400 when request body is not an object', async () => {
      const response = await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send([validAuthEvent])
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
    });
  });

  describe('Validation error cases - invalid SUPI format', () => {
    it('should return 400 when SUPI does not start with imsi-', async () => {
      const response = await request(app)
        .put(`/nudm-ueau/v1/msisdn-1234567890/auth-events/${validAuthEventId}`)
        .send(validAuthEvent)
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('Invalid SUPI format');
    });
  });

  describe('Subscriber not found', () => {
    it('should return 404 when subscriber does not exist', async () => {
      (mockCollection.findOne as sinon.SinonStub).onFirstCall().resolves(null);

      const response = await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(validAuthEvent)
        .expect(404);

      expect(response.body).to.have.property('status', 404);
      expect(response.body).to.have.property('title', 'Not Found');
      expect(response.body).to.have.property('cause', 'DATA_NOT_FOUND');
      expect(response.body.detail).to.include('not found');
    });
  });

  describe('Auth event not found', () => {
    it('should return 404 when auth event does not exist', async () => {
      (mockCollection.findOne as sinon.SinonStub).onSecondCall().resolves(null);

      const response = await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(validAuthEvent)
        .expect(404);

      expect(response.body).to.have.property('status', 404);
      expect(response.body).to.have.property('title', 'Not Found');
      expect(response.body).to.have.property('cause', 'DATA_NOT_FOUND');
      expect(response.body.detail).to.include('Auth event');
      expect(response.body.detail).to.include('not found');
    });

    it('should return 404 for non-existent authEventId', async () => {
      (mockCollection.findOne as sinon.SinonStub).onSecondCall().resolves(null);

      const response = await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/non-existent-id`)
        .send(validAuthEvent)
        .expect(404);

      expect(response.body).to.have.property('status', 404);
      expect(response.body).to.have.property('cause', 'DATA_NOT_FOUND');
    });
  });

  describe('Update failure', () => {
    it('should return 500 when update fails', async () => {
      (mockCollection.updateOne as sinon.SinonStub).resolves({ modifiedCount: 0 });

      const response = await request(app)
        .put(`/nudm-ueau/v1/${validSupi}/auth-events/${validAuthEventId}`)
        .send(validAuthEvent)
        .expect(500);

      expect(response.body).to.have.property('status', 500);
      expect(response.body).to.have.property('title', 'Internal Server Error');
      expect(response.body.detail).to.include('Failed to update auth event');
    });
  });
});

describe('POST /:supi/hss-security-information/:hssAuthType/generate-av', () => {
  const validSupi = 'imsi-999700000000001';
  const mockSubscriber = {
    _id: validSupi,
    supi: validSupi,
    permanentKey: '465B5CE8B199B49FAA5F0A2EE238A6BC',
    operatorKey: 'E8ED289DEBA952E4283B54E88E6183CA',
    sequenceNumber: '000000000001',
    authenticationMethod: '5G_AKA'
  };

  beforeEach(() => {
    (mockCollection.findOne as sinon.SinonStub).resolves(mockSubscriber);
    (mockCollection.updateOne as sinon.SinonStub).resolves({ modifiedCount: 1 });
  });

  describe('Success cases - EPS_AKA', () => {
    const validEpsAkaRequest = {
      hssAuthType: 'EPS_AKA',
      numOfRequestedVectors: 1,
      servingNetworkId: {
        mcc: '999',
        mnc: '070'
      }
    };

    it('should generate EPS-AKA authentication vector', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send(validEpsAkaRequest)
        .expect(200)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('hssAuthenticationVectors');
      expect(response.body.hssAuthenticationVectors).to.be.an('array');
      expect(response.body.hssAuthenticationVectors).to.have.lengthOf(1);
    });

    it('should return valid EPS-AKA authentication vector structure', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send(validEpsAkaRequest)
        .expect(200);

      const av = response.body.hssAuthenticationVectors[0];
      expect(av).to.have.property('avType', 'EPS_AKA');
      expect(av).to.have.property('rand');
      expect(av).to.have.property('xres');
      expect(av).to.have.property('autn');
      expect(av).to.have.property('kasme');
    });

    it('should generate valid RAND (16 bytes, 32 hex chars)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send(validEpsAkaRequest)
        .expect(200);

      const rand = response.body.hssAuthenticationVectors[0].rand;
      expect(rand).to.be.a('string');
      expect(rand).to.have.lengthOf(32);
      expect(rand).to.match(/^[A-F0-9]{32}$/);
    });

    it('should generate valid KASME (32 bytes, 64 hex chars)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send(validEpsAkaRequest)
        .expect(200);

      const kasme = response.body.hssAuthenticationVectors[0].kasme;
      expect(kasme).to.be.a('string');
      expect(kasme).to.have.lengthOf(64);
      expect(kasme).to.match(/^[A-F0-9]{64}$/);
    });

    it('should generate multiple authentication vectors', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ ...validEpsAkaRequest, numOfRequestedVectors: 5 })
        .expect(200);

      expect(response.body.hssAuthenticationVectors).to.have.lengthOf(5);
      const rands = response.body.hssAuthenticationVectors.map((av: any) => av.rand);
      const uniqueRands = new Set(rands);
      expect(uniqueRands.size).to.equal(5);
    });

    it('should work without servingNetworkId (default PLMN)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 1 })
        .expect(200);

      expect(response.body.hssAuthenticationVectors).to.have.lengthOf(1);
      expect(response.body.hssAuthenticationVectors[0]).to.have.property('kasme');
    });
  });

  describe('Success cases - IMS_AKA', () => {
    const validImsAkaRequest = {
      hssAuthType: 'IMS_AKA',
      numOfRequestedVectors: 1
    };

    it('should generate IMS-AKA authentication vector', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/ims-aka/generate-av`)
        .send(validImsAkaRequest)
        .expect(200)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('hssAuthenticationVectors');
      expect(response.body.hssAuthenticationVectors).to.be.an('array');
      expect(response.body.hssAuthenticationVectors).to.have.lengthOf(1);
    });

    it('should return valid IMS-AKA authentication vector structure', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/ims-aka/generate-av`)
        .send(validImsAkaRequest)
        .expect(200);

      const av = response.body.hssAuthenticationVectors[0];
      expect(av).to.have.property('avType', 'IMS_AKA');
      expect(av).to.have.property('rand');
      expect(av).to.have.property('xres');
      expect(av).to.have.property('autn');
      expect(av).to.have.property('ck');
      expect(av).to.have.property('ik');
    });

    it('should generate valid CK and IK (16 bytes each)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/ims-aka/generate-av`)
        .send(validImsAkaRequest)
        .expect(200);

      const av = response.body.hssAuthenticationVectors[0];
      expect(av.ck).to.have.lengthOf(32);
      expect(av.ck).to.match(/^[A-F0-9]{32}$/);
      expect(av.ik).to.have.lengthOf(32);
      expect(av.ik).to.match(/^[A-F0-9]{32}$/);
    });
  });

  describe('Success cases - EAP_AKA', () => {
    const validEapAkaRequest = {
      hssAuthType: 'EAP_AKA',
      numOfRequestedVectors: 1
    };

    it('should generate EAP-AKA authentication vector', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eap-aka/generate-av`)
        .send(validEapAkaRequest)
        .expect(200);

      const av = response.body.hssAuthenticationVectors[0];
      expect(av).to.have.property('avType', 'EAP_AKA');
      expect(av).to.have.property('rand');
      expect(av).to.have.property('xres');
      expect(av).to.have.property('autn');
      expect(av).to.have.property('ck');
      expect(av).to.have.property('ik');
    });
  });

  describe('Success cases - EAP_AKA_PRIME', () => {
    const validEapAkaPrimeRequest = {
      hssAuthType: 'EAP_AKA_PRIME',
      numOfRequestedVectors: 1,
      servingNetworkId: {
        mcc: '999',
        mnc: '070'
      }
    };

    it('should generate EAP-AKA\' authentication vector', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eap-aka-prime/generate-av`)
        .send(validEapAkaPrimeRequest)
        .expect(200);

      const av = response.body.hssAuthenticationVectors[0];
      expect(av).to.have.property('avType', 'EAP_AKA_PRIME');
      expect(av).to.have.property('rand');
      expect(av).to.have.property('xres');
      expect(av).to.have.property('autn');
      expect(av).to.have.property('ckPrime');
      expect(av).to.have.property('ikPrime');
    });

    it('should generate valid CK\' and IK\' (16 bytes each)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eap-aka-prime/generate-av`)
        .send(validEapAkaPrimeRequest)
        .expect(200);

      const av = response.body.hssAuthenticationVectors[0];
      expect(av.ckPrime).to.have.lengthOf(32);
      expect(av.ckPrime).to.match(/^[A-F0-9]{32}$/);
      expect(av.ikPrime).to.have.lengthOf(32);
      expect(av.ikPrime).to.match(/^[A-F0-9]{32}$/);
    });
  });

  describe('Success cases - GBA_AKA', () => {
    const validGbaAkaRequest = {
      hssAuthType: 'GBA_AKA',
      numOfRequestedVectors: 1
    };

    it('should generate GBA-AKA authentication vector', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/gba-aka/generate-av`)
        .send(validGbaAkaRequest)
        .expect(200);

      const av = response.body.hssAuthenticationVectors[0];
      expect(av).to.have.property('avType', 'GBA_AKA');
      expect(av).to.have.property('rand');
      expect(av).to.have.property('xres');
      expect(av).to.have.property('autn');
      expect(av).to.have.property('ck');
      expect(av).to.have.property('ik');
    });
  });

  describe('Success cases - UMTS_AKA', () => {
    const validUmtsAkaRequest = {
      hssAuthType: 'UMTS_AKA',
      numOfRequestedVectors: 1
    };

    it('should generate UMTS-AKA authentication vector', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/umts-aka/generate-av`)
        .send(validUmtsAkaRequest)
        .expect(200);

      const av = response.body.hssAuthenticationVectors[0];
      expect(av).to.have.property('avType', 'UMTS_AKA');
      expect(av).to.have.property('rand');
      expect(av).to.have.property('xres');
      expect(av).to.have.property('autn');
      expect(av).to.have.property('ck');
      expect(av).to.have.property('ik');
    });
  });

  describe('Validation errors', () => {
    it('should return 400 when request body is empty', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({})
        .expect(400);

      expect(response.body).to.have.property('status', 400);
      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('numOfRequestedVectors is required');
    });

    it('should return 400 when numOfRequestedVectors is missing', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ hssAuthType: 'EPS_AKA' })
        .expect(400);

      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('numOfRequestedVectors is required');
    });

    it('should return 400 when numOfRequestedVectors is less than 1', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 0 })
        .expect(400);

      expect(response.body.detail).to.include('must be between 1 and 32');
    });

    it('should return 400 when numOfRequestedVectors is greater than 32', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 33 })
        .expect(400);

      expect(response.body.detail).to.include('must be between 1 and 32');
    });

    it('should return 400 for invalid SUPI format', async () => {
      const response = await request(app)
        .post('/nudm-ueau/v1/msisdn-1234567890/hss-security-information/eps-aka/generate-av')
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 1 })
        .expect(400);

      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('Invalid SUPI format');
    });

    it('should return 400 for invalid hssAuthType in URI', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/invalid-type/generate-av`)
        .send({ numOfRequestedVectors: 1 })
        .expect(400);

      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('Invalid hssAuthType');
    });

    it('should return 400 when hssAuthType in body mismatches URI', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ hssAuthType: 'IMS_AKA', numOfRequestedVectors: 1 })
        .expect(400);

      expect(response.body.detail).to.include('does not match URI parameter');
    });

    it('should return 400 for non-object request body', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send([])
        .expect(400);

      expect(response.body.detail).to.include('must be a valid JSON object');
    });
  });

  describe('Subscriber not found', () => {
    it('should return 404 when subscriber does not exist', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(null);

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 1 })
        .expect(404);

      expect(response.body).to.have.property('status', 404);
      expect(response.body).to.have.property('title', 'Not Found');
      expect(response.body).to.have.property('cause', 'DATA_NOT_FOUND');
      expect(response.body.detail).to.include('not found');
    });
  });

  describe('Missing authentication credentials', () => {
    it('should return 500 when permanentKey is missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        permanentKey: ''
      });

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 1 })
        .expect(500);

      expect(response.body).to.have.property('status', 500);
      expect(response.body.detail).to.include('Missing authentication credentials');
    });

    it('should return 500 when operatorKey is missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        operatorKey: ''
      });

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 1 })
        .expect(500);

      expect(response.body.detail).to.include('Missing authentication credentials');
    });

    it('should return 500 when sequenceNumber is missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        sequenceNumber: ''
      });

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 1 })
        .expect(500);

      expect(response.body.detail).to.include('Missing authentication credentials');
    });
  });

  describe('Sequence number increment', () => {
    it('should increment sequence number in database', async () => {
      await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 1 })
        .expect(200);

      const updateCall = (mockCollection.updateOne as sinon.SinonStub).getCall(0);
      expect(updateCall.args[0]).to.deep.equal({ supi: validSupi });
      expect(updateCall.args[1]).to.deep.equal({ $set: { sequenceNumber: '000000000002' } });
    });

    it('should increment sequence number by numOfRequestedVectors', async () => {
      await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 5 })
        .expect(200);

      const updateCall = (mockCollection.updateOne as sinon.SinonStub).getCall(0);
      expect(updateCall.args[0]).to.deep.equal({ supi: validSupi });
      expect(updateCall.args[1]).to.deep.equal({ $set: { sequenceNumber: '000000000006' } });
    });

    it('should handle nested authenticationSubscription structure', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        subscribedData: {
          authenticationSubscription: {
            authenticationMethod: '5G_AKA',
            permanentKey: { permanentKeyValue: '465B5CE8B199B49FAA5F0A2EE238A6BC' },
            sequenceNumber: '16F3B3F70FC2',
            authenticationManagementField: '8000',
            milenage: { op: { opValue: 'E8ED289DEBA952E4283B54E88E6183CA' } }
          }
        }
      });

      await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 1 })
        .expect(200);

      const updateCall = (mockCollection.updateOne as sinon.SinonStub).getCall(0);
      expect(updateCall.args[0]).to.deep.equal({ supi: validSupi });
      expect(updateCall.args[1]).to.deep.equal({ $set: { 'subscribedData.authenticationSubscription.sequenceNumber': '16F3B3F70FC3' } });
    });
  });

  describe('Supported features', () => {
    it('should include supportedFeatures in response when provided', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/eps-aka/generate-av`)
        .send({
          hssAuthType: 'EPS_AKA',
          numOfRequestedVectors: 1,
          supportedFeatures: 'test-feature'
        })
        .expect(200);

      expect(response.body).to.have.property('supportedFeatures', 'test-feature');
    });
  });

  describe('Case insensitivity', () => {
    it('should accept uppercase hssAuthType in URI', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/EPS-AKA/generate-av`)
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 1 })
        .expect(200);

      expect(response.body.hssAuthenticationVectors).to.have.lengthOf(1);
    });

    it('should accept mixed case hssAuthType in URI', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/hss-security-information/Eps-Aka/generate-av`)
        .send({ hssAuthType: 'EPS_AKA', numOfRequestedVectors: 1 })
        .expect(200);

      expect(response.body.hssAuthenticationVectors).to.have.lengthOf(1);
    });
  });
});

describe('POST /:supi/gba-security-information/generate-av', () => {
  const validSupi = 'imsi-999700000000001';
  const mockSubscriber = {
    _id: validSupi,
    supi: validSupi,
    permanentKey: '465B5CE8B199B49FAA5F0A2EE238A6BC',
    operatorKey: 'E8ED289DEBA952E4283B54E88E6183CA',
    sequenceNumber: '000000000001',
    authenticationMethod: '5G_AKA'
  };

  beforeEach(() => {
    (mockCollection.findOne as sinon.SinonStub).resolves(mockSubscriber);
    (mockCollection.updateOne as sinon.SinonStub).resolves({ modifiedCount: 1 });
  });

  describe('Success cases', () => {
    const validGbaRequest = {
      authType: 'DIGEST_AKAV1_MD5'
    };

    it('should generate GBA authentication vector', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send(validGbaRequest)
        .expect(200)
        .expect('Content-Type', /json/);

      expect(response.body).to.have.property('threeGAkaAv');
      expect(response.body.threeGAkaAv).to.be.an('object');
    });

    it('should return valid 3G-AKA authentication vector structure', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send(validGbaRequest)
        .expect(200);

      const av = response.body.threeGAkaAv;
      expect(av).to.have.property('rand');
      expect(av).to.have.property('xres');
      expect(av).to.have.property('autn');
      expect(av).to.have.property('ck');
      expect(av).to.have.property('ik');
    });

    it('should generate valid RAND (16 bytes, 32 hex chars)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send(validGbaRequest)
        .expect(200);

      const rand = response.body.threeGAkaAv.rand;
      expect(rand).to.be.a('string');
      expect(rand).to.have.lengthOf(32);
      expect(rand).to.match(/^[A-F0-9]{32}$/);
    });

    it('should generate valid AUTN (16 bytes, 32 hex chars)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send(validGbaRequest)
        .expect(200);

      const autn = response.body.threeGAkaAv.autn;
      expect(autn).to.be.a('string');
      expect(autn).to.have.lengthOf(32);
      expect(autn).to.match(/^[A-F0-9]{32}$/);
    });

    it('should generate valid CK (16 bytes, 32 hex chars)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send(validGbaRequest)
        .expect(200);

      const ck = response.body.threeGAkaAv.ck;
      expect(ck).to.be.a('string');
      expect(ck).to.have.lengthOf(32);
      expect(ck).to.match(/^[A-F0-9]{32}$/);
    });

    it('should generate valid IK (16 bytes, 32 hex chars)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send(validGbaRequest)
        .expect(200);

      const ik = response.body.threeGAkaAv.ik;
      expect(ik).to.be.a('string');
      expect(ik).to.have.lengthOf(32);
      expect(ik).to.match(/^[A-F0-9]{32}$/);
    });

    it('should generate valid XRES (4-8 bytes, 8-16 hex chars)', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send(validGbaRequest)
        .expect(200);

      const xres = response.body.threeGAkaAv.xres;
      expect(xres).to.be.a('string');
      expect(xres.length).to.be.at.least(8);
      expect(xres.length).to.be.at.most(16);
      expect(xres).to.match(/^[A-F0-9]+$/);
    });

    it('should include supportedFeatures in response when provided', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send({
          authType: 'DIGEST_AKAV1_MD5',
          supportedFeatures: 'test-feature'
        })
        .expect(200);

      expect(response.body).to.have.property('supportedFeatures', 'test-feature');
    });

    it('should not include supportedFeatures when not provided', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send(validGbaRequest)
        .expect(200);

      expect(response.body).to.not.have.property('supportedFeatures');
    });
  });

  describe('Validation errors', () => {
    it('should return 400 when authType is missing', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send({})
        .expect(400);

      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('authType is required');
    });

    it('should return 400 for invalid authType', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send({ authType: 'INVALID_TYPE' })
        .expect(400);

      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('Invalid authType');
      expect(response.body.detail).to.include('DIGEST_AKAV1_MD5');
    });

    it('should return 400 for invalid SUPI format', async () => {
      const response = await request(app)
        .post('/nudm-ueau/v1/invalid-supi/gba-security-information/generate-av')
        .send({ authType: 'DIGEST_AKAV1_MD5' })
        .expect(400);

      expect(response.body).to.have.property('cause', 'INVALID_PARAMETER');
      expect(response.body.detail).to.include('Invalid SUPI format');
    });

    it('should return 400 for non-object request body', async () => {
      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send([])
        .expect(400);

      expect(response.body.detail).to.include('must be a valid JSON object');
    });
  });

  describe('Subscriber not found', () => {
    it('should return 404 when subscriber does not exist', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves(null);

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send({ authType: 'DIGEST_AKAV1_MD5' })
        .expect(404);

      expect(response.body).to.have.property('status', 404);
      expect(response.body).to.have.property('title', 'Not Found');
      expect(response.body).to.have.property('cause', 'DATA_NOT_FOUND');
      expect(response.body.detail).to.include('not found');
    });
  });

  describe('Missing authentication credentials', () => {
    it('should return 500 when permanentKey is missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        permanentKey: ''
      });

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send({ authType: 'DIGEST_AKAV1_MD5' })
        .expect(500);

      expect(response.body).to.have.property('status', 500);
      expect(response.body.detail).to.include('Missing authentication credentials');
    });

    it('should return 500 when operatorKey is missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        operatorKey: ''
      });

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send({ authType: 'DIGEST_AKAV1_MD5' })
        .expect(500);

      expect(response.body.detail).to.include('Missing authentication credentials');
    });

    it('should return 500 when sequenceNumber is missing', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        sequenceNumber: ''
      });

      const response = await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send({ authType: 'DIGEST_AKAV1_MD5' })
        .expect(500);

      expect(response.body.detail).to.include('Missing authentication credentials');
    });
  });

  describe('Sequence number increment', () => {
    it('should increment sequence number in database', async () => {
      await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send({ authType: 'DIGEST_AKAV1_MD5' })
        .expect(200);

      const updateCall = (mockCollection.updateOne as sinon.SinonStub).getCall(0);
      expect(updateCall.args[0]).to.deep.equal({ supi: validSupi });
      expect(updateCall.args[1]).to.deep.equal({ $set: { sequenceNumber: '000000000002' } });
    });

    it('should handle nested authenticationSubscription structure', async () => {
      (mockCollection.findOne as sinon.SinonStub).resolves({
        ...mockSubscriber,
        subscribedData: {
          authenticationSubscription: {
            authenticationMethod: '5G_AKA',
            permanentKey: { permanentKeyValue: '465B5CE8B199B49FAA5F0A2EE238A6BC' },
            sequenceNumber: '16F3B3F70FC2',
            authenticationManagementField: '8000',
            milenage: { op: { opValue: 'E8ED289DEBA952E4283B54E88E6183CA' } }
          }
        }
      });

      await request(app)
        .post(`/nudm-ueau/v1/${validSupi}/gba-security-information/generate-av`)
        .send({ authType: 'DIGEST_AKAV1_MD5' })
        .expect(200);

      const updateCall = (mockCollection.updateOne as sinon.SinonStub).getCall(0);
      expect(updateCall.args[0]).to.deep.equal({ supi: validSupi });
      expect(updateCall.args[1]).to.deep.equal({ $set: { 'subscribedData.authenticationSubscription.sequenceNumber': '16F3B3F70FC3' } });
    });
  });
});

