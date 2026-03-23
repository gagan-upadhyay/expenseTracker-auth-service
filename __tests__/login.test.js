// ---------------------------------------------
// 1. MOCKS FIRST
// ---------------------------------------------
import { expect, jest } from "@jest/globals";

jest.unstable_mockModule("../src/model/userModel.js", () => ({
  findUserByEmail: jest.fn(async (email) => {
    if (email === "abcd@asn.com") {
      return {
        id: "test-id",
        auth_type: "PASSWORD",
        password:
          "$2b$12$Ppq.uQjHYp8kO3S2sx0GZOPlsqyKGAvFaMZL3Rxfc2t4fr8nY3niO",
      };
    }
    return null; // user not found -> triggers 404
  }),

  // required by other services to be mocks:
  insertUser: jest.fn(),
  insertOAuthUser: jest.fn(),
  insertEmailOnlyUser: jest.fn(),
  updateField: jest.fn(),
}));

// Mock DB
jest.unstable_mockModule("../config/dbconnection.js", () => ({
  pgQuery: jest.fn(async (query, params) => {
    if (params[0] === "abcd@asn.com") {
      return {
        rows: [
          {
            id: "test-id",
            auth_type: "PASSWORD",
            password:
              "$2b$12$Ppq.uQjHYp8kO3S2sx0GZOPlsqyKGAvFaMZL3Rxfc2t4fr8nY3niO",
          },
        ],
      };
    }
    return { rows: [] };
  }),
  pgConnectTest: jest.fn(async () => true),
  pool: { end: jest.fn(async () => {}) }
}));

// Mock Redis
jest.unstable_mockModule("../config/redisConnection.js", () => ({
  getRedisClient: async () => ({
    connect: async () => {},
    disconnect: async () => {},
    on: () => {},
    set: jest.fn(async () => "OK"),   // <--- FIXED
    get: jest.fn(async () => null),
    expire: jest.fn(async () => {})
  }),
}));

// Mock bcrypt
jest.unstable_mockModule("bcrypt", () => ({
  compare: jest.fn((plain, hashed) => plain === "12345678")
}));

// ---------------------------------------------
// 2. IMPORT APP AFTER MOCKS
// ---------------------------------------------
const { app } = await import("../index.js");
import request from "supertest";

// ---------------------------------------------
// 3. TESTS
// ---------------------------------------------
describe("POST /login", () => {
  it("should return 200 and token for valid credentials", async () => {
    const res = await request(app)
      .post("/api/v1/auth/login")
      .send({
        email: "abcd@asn.com",
        password: "12345678",
      });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty("accessToken");
  });
  
  it("should return 400 for missing password", async ()=>{
    const res = await request(app)
    .post('/api/v1/auth/login')
    .send({
        email: "abcd@asn.com"
    });
    expect(res.status).toBe(400);
    expect(res.body).toHaveProperty("error");
  });

  it("should return 401 for wrong password", async ()=>{
    const res = await request(app)
    .post('/api/v1/auth/login')
    .send({
        email: "abcd@asn.com",
        password:"1234567890"
    });
    expect(res.status).toBe(401);
    expect(res.body).toHaveProperty("error");
  });

  it("should return 404 for non-existing user", async () => {
    const res = await request(app)
      .post("/api/v1/auth/login")
      .send({
        email: "wrong@asn.com",
        password: "bad-pass",
      });

    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty("error");
  });
});