process.env.INVITE_SERVICE_URL = 'http://invite-service:3002'

import { mockDeep} from 'jest-mock-extended'
import { PrismaClient } from '@prisma/client'
import * as bcrypt from 'bcryptjs'
import axios from 'axios'

// mock prisma
jest.mock('../prisma/client.prisma', () => ({
	__esModule: true,
	default: mockDeep<PrismaClient>(),
}))
const prismaMock = require('../prisma/client.prisma').default

// mock other utilities
jest.mock('../utils/hash', () => ({
	hashPassword: jest.fn().mockResolvedValue('hashed_pw'),
	comparePassword: jest.fn().mockResolvedValue(true),
}))

jest.mock('../utils/jwt', () => ({
	generateAccessToken: jest.fn().mockReturnValue('access_token'),
	generateRefreshToken: jest.fn().mockReturnValue('refresh_token'),
	verifyToken: jest.fn().mockReturnValue({ userId: 'u1', tokenId: 't1' }),
}))

jest.mock('../utils/totp', () => ({
	generateTOTPSecret: jest.fn().mockReturnValue({
		base32: 'base32secret',
		otpauth_url: 'otpauth://example',
	}),
	verifyTOTP: jest.fn().mockReturnValue(true),
}))

jest.mock('../utils/mailer', () => ({
	sendMail: jest.fn().mockResolvedValue(true),
}))

jest.mock('axios')
const mockedAxios = jest.mocked(axios)

// Mock bcrypt.compare for rotateRefreshToken test
jest.mock('bcryptjs', () => ({
	compare: jest.fn(),
}))
const mockedCompare = (jest.mocked(bcrypt.compare) as jest.Mock).mockResolvedValue(true)

import * as authService from '../services/auth.service'
import { sendMail } from '../utils/mailer'

describe('auth.service', () => {
	beforeEach(() => {
		jest.clearAllMocks()
	})

	describe('registerWithInvitation', () => {
		it('registers a user and marks invitation used', async () => {
			prismaMock.user.findUnique.mockResolvedValue(null)
			prismaMock.user.create.mockResolvedValue({
				id: 'u1',
				email: 'test@mail.com',
				role: 'CLIENT_USER',
			})
			prismaMock.refreshToken.create.mockResolvedValue({} as any)
			const invite = { id: 'inv1', email: 'test@mail.com', role: 'CLIENT_USER' }

			const result = await authService.registerWithInvitation(invite, 'John', 'pass123')

			expect(prismaMock.user.create).toHaveBeenCalled()
			expect(mockedAxios.post).toHaveBeenCalledWith(
				'http://invite-service:3002/api/v1/invites/mark-used',
				{ inviteId: 'inv1' }
			)
			expect(result).toMatchObject({
				user: { id: 'u1', email: 'test@mail.com', role: 'CLIENT_USER' },
				accessToken: 'access_token',
				refreshToken: 'refresh_token'
			})
		})

		it('throws if user already exists', async () => {
			prismaMock.user.findUnique.mockResolvedValue({ id: 'u1' } as any)
			await expect(
				authService.registerWithInvitation({ email: 'test@mail.com' }, 'John', 'pass')
			).rejects.toMatchObject({ status: 400 })
		})
  	})

	describe('login', () => {
		it('logs in successfully', async () => {
			prismaMock.user.findUnique.mockResolvedValue({
				id: 'u1',
				email: 'a@a.com',
				password: 'hashed_pw',
			})
			prismaMock.refreshToken.create.mockResolvedValue({} as any)

			const result = await authService.login('a@a.com', 'pass')
			expect(result).toMatchObject({
				accessToken: 'access_token',
				refreshToken: 'refresh_token',
			})
		})

		it('throws if password mismatch', async () => {
			const hash = require('../utils/hash')
			hash.comparePassword.mockResolvedValue(false)
			prismaMock.user.findUnique.mockResolvedValue({ password: 'wrong' })

			// re-import the service AFTER mocking
			const authService = require('../services/auth.service')

			await expect(authService.login('a@a.com', 'bad')).rejects.toMatchObject({
				status: 400,
			})
		})
	})

	describe('enable2FA', () => {
		it('enables 2FA for a user', async () => {
			prismaMock.user.findUnique.mockResolvedValue({
				id: 'u1',
				email: 'user@mail.com',
			})
			prismaMock.user.update.mockResolvedValue({} as any)

			const res = await authService.enable2FA('u1')
			expect(res.secret).toBe('base32secret')
			expect(prismaMock.user.update).toHaveBeenCalled()
		})
	})

	describe('rotateRefreshToken', () => {
		it('rotates refresh token successfully', async () => {
			prismaMock.refreshToken.findUnique.mockResolvedValue({
				id: 't1',
				userId: 'u1',
				tokenHash: 'hash',
				revoked: false,
				expiresAt: new Date(Date.now() + 100000),
			})
			prismaMock.$transaction.mockResolvedValue([] as any)
			prismaMock.user.findUnique.mockResolvedValue({ id: 'u1' })

			const res = await authService.rotateRefreshToken('some_token')
			expect(res.accessToken).toBe('access_token')
			expect(res.refreshToken).toBe('refresh_token')
		})
	})

	describe('requestPasswordReset', () => {
		it('creates OTP and sends mail', async () => {
			prismaMock.user.findUnique.mockResolvedValue({ id: 'u1', email: 'a@a.com' })
			prismaMock.otp.create.mockResolvedValue({} as any)

			await authService.requestPasswordReset('a@a.com')
			expect(sendMail).toHaveBeenCalled()
		})
	})
})
