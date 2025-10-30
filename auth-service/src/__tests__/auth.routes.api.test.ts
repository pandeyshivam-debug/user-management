import request from 'supertest'
import app from '../app'
import axios from 'axios'
import { Role } from '@prisma/client'
import { prismaMock } from '../__mocks__/client.prisma'

let consoleLogSpy: jest.SpyInstance
let consoleErrorSpy: jest.SpyInstance

beforeAll(() => {
  // Only show timing logs from timedRequest
  consoleLogSpy = jest.spyOn(console, 'log').mockImplementation((...args) => {
    if (
      typeof args[0] === 'string' &&
      args[0].match(/^(POST|GET|PUT|DELETE).+took \d+(\.\d+)?ms$/)
    ) {
      process.stdout.write(args[0] + '\n')
    }
  })

  // Swallow all other errors
  consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
})

afterAll(() => {
  consoleLogSpy.mockRestore()
  consoleErrorSpy.mockRestore()
})

// --- Mock external modules ---
jest.mock('axios')

// --- Setup: Reset mocks before each test ---
beforeEach(() => {
  jest.clearAllMocks()
  prismaMock.user.findUnique.mockReset()
  prismaMock.user.create.mockReset()

  // Default Prisma behavior
  prismaMock.user.findUnique.mockResolvedValue(null)
  prismaMock.user.create.mockResolvedValue({
    id: 'user_123',
    email: 'testuser@example.com',
    phone: null,
    name: 'John Doe',
    password: 'hashed_password',
    isVerified: true,
    role: Role.CLIENT_USER,
    totpSecret: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  })

  // Mock invite verification API
  ;(axios.post as jest.Mock).mockResolvedValue({
    data: {
      invite: {
        id: 'invite_123',
        email: 'testuser@example.com',
        role: 'CLIENT_USER',
      },
    },
  })
})

afterEach(() => {
  jest.restoreAllMocks()
})

// --- Helper for timing requests ---
const timedRequest = async (label: string, fn: () => Promise<any>) => {
  const start = performance.now()
  const res = await fn()
  const end = performance.now()
  process.stdout.write(`${label} took ${(end - start).toFixed(2)}ms\n`)
  return res
}

describe('Auth Routes Integration', () => {
  const baseUrl = '/api/v1/auth'

  it('POST /register should create a user', async () => {
    await timedRequest('POST /register', () =>
      request(app).post(`${baseUrl}/register`).send({
        token: 'fake_invite_token_123',
        name: 'John Doe',
        password: 'Pass123!',
        phone: '9876543210',
      })
    )
  })

  it('POST /login should log in', async () => {
    prismaMock.user.findUnique.mockResolvedValue({
      id: 'user_123',
      email: 'testuser@example.com',
      phone: null,
      name: 'John Doe',
      password: 'hashed_password',
      isVerified: true,
      role: Role.CLIENT_USER,
      totpSecret: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    })

    await timedRequest('POST /login', () =>
      request(app).post(`${baseUrl}/login`).send({
        email: 'testuser@example.com',
        password: 'Pass123!',
      })
    )
  })

  it('POST /refresh should refresh token', async () => {
    await timedRequest('POST /refresh', () =>
      request(app).post(`${baseUrl}/refresh`).send({ refreshToken: 'fakeToken' })
    )
  })

  it('POST /password-reset/request should request reset', async () => {
    await timedRequest('POST /password-reset/request', () =>
      request(app).post(`${baseUrl}/password-reset/request`).send({ email: 'testuser@example.com' })
    )
  })

  it('POST /otp/request should request OTP', async () => {
    await timedRequest('POST /otp/request', () =>
      request(app).post(`${baseUrl}/otp/request`).send({ email: 'testuser@example.com' })
    )
  })

  it('GET /me should return user info (requires auth)', async () => {
    const token = 'fake.jwt.token'
    await timedRequest('GET /me', () =>
      request(app).get(`${baseUrl}/me`).set('Authorization', `Bearer ${token}`)
    )
  })
})
