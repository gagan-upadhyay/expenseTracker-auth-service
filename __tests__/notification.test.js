import { expect, jest } from '@jest/globals';

// Mock subscription model
jest.unstable_mockModule('../src/subscriptionModel.js', () => ({
  saveSubscription: jest.fn(async () => {}),
  deleteSubscription: jest.fn(async () => {}),
  cleanupOldSubscriptions:jest.fn(async()=>{}),
  listSubscriptions:jest.fn(async()=>{}),
  getSubscription: jest.fn(async (userId) => ({ endpoint: 'https://example.com', keys: { p256dh: 'p256dh-key', auth: 'auth-key' } })),
}));

// Mock push service
jest.unstable_mockModule('../src/services/pushService.js', () => ({
  sendNotification: jest.fn(async () => true),
}));

// Mock verifySession to inject req.user
jest.unstable_mockModule('../middleware/verifySession.js', () => ({
  verifySession: (req, res, next) => {
    req.user = { id: 'test-user' };
    return next();
  }
}));

const { app } = await import('../index.js');
import request from 'supertest';

describe('Notification endpoints', () => {
  it('should subscribe successfully', async () => {
    const res = await request(app)
      .post('/api/v1/auth/notifications/subscribe')
      .send({ endpoint: 'https://example.com', keys: { p256dh: 'p256', auth: 'a' } });

    expect(res.status).toBe(201);
  });

  it('should unsubscribe successfully', async () => {
    const res = await request(app)
      .post('/api/v1/auth/notifications/unsubscribe')
      .send();

    expect(res.status).toBe(200);
  });

  it('should send test notification', async () => {
    const res = await request(app)
      .post('/api/v1/auth/notifications/send-test')
      .send({ userId: 'test-user', payload: { title: 'hi', body: 'there' } });

    expect(res.status).toBe(200);
  });
});