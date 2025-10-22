process.env.INVITE_SERVICE_URL = 'http://invite-service:3002'

import { Request, Response, NextFunction } from 'express'
import * as controller from '../controllers/auth.controller' 
import axios from 'axios'

jest.mock('../services/auth.service', () => ({
	registerWithInvitation: jest.fn(),
	login: jest.fn(),
	enable2FA: jest.fn(),
	verify2FA: jest.fn(),
	rotateRefreshToken: jest.fn(),
	revokeRefreshToken: jest.fn(),
	requestPasswordReset: jest.fn(),
	confirmPasswordReset: jest.fn(),
	requestLoginOTP: jest.fn(),
	verifyLoginOTP: jest.fn(),
}))

const authService = jest.requireMock('../services/auth.service')

jest.mock('axios')
const mockedAxios = axios as jest.Mocked<typeof axios>

jest.mock('../middleware/validator.middleware', () => ({
	registerSchema: { parse: (v: any) => v },
	loginSchema: { parse: (v: any) => v },
	refreshSchema: { parse: (v: any) => v },
	requestResetSchema: { parse: (v: any) => v },
	confirmResetSchema: { parse: (v: any) => v },
	requestOTPSchema: { parse: (v: any) => v },
	verifyOTPSchema: { parse: (v: any) => v },
}))

function mockResponse() {
	const res: Partial<Response> = {}
	res.status = jest.fn().mockReturnValue(res)
	res.json = jest.fn().mockReturnValue(res)
	res.send = jest.fn().mockReturnValue(res)
	return res as Response
}

function mockNext() {
	return jest.fn() as unknown as NextFunction
}

describe('auth.controller', () => {
	beforeEach(() => {
	jest.clearAllMocks()

	process.env.INVITE_SERVICE_URL = 'http://invite-service:3002'
	})

	describe('register', () => {
		it('calls invite service via axios and registers user with invite', async () => {
			// arrange
			const invite = { id: 'inv-1', email: 'a@b.com' }
			mockedAxios.post.mockResolvedValueOnce({ data: { invite } })

			;(authService.registerWithInvitation as jest.Mock).mockResolvedValueOnce({
			id: 'user-1',
			email: 'a@b.com',
			})

			const req = {
			body: { token: 'tok', name: 'Alice', password: 'pass', phone: '987' },
			} as Partial<Request> as Request
			const res = mockResponse()
			const next = mockNext()

			// act
			await controller.register(req, res, next)

			// assert
			expect(mockedAxios.post).toHaveBeenCalledWith(
				`${process.env.INVITE_SERVICE_URL}/api/v1/invite/verify`,
				{ token: 'tok' }
			)
			expect(authService.registerWithInvitation).toHaveBeenCalledWith(
				invite,
				'Alice',
				'pass',
				'987'
			)
			expect(res.json).toHaveBeenCalledWith({
				id: 'user-1',
				email: 'a@b.com',
			})
		})

		it('passes errors to next if axios fails', async () => {
			mockedAxios.post.mockRejectedValueOnce(new Error('invite not found'))

			const req = { body: { token: 'bad' } } as Partial<Request> as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.register(req, res, next)

			expect(next).toHaveBeenCalled()
		})
	})

	describe('login', () => {
		it('calls authService.login and returns result', async () => {
			;(authService.login as jest.Mock).mockResolvedValueOnce({ token: 't' })

			const req = {
			body: { email: 'x@y.com', password: 'secret', totp: undefined },
			} as Partial<Request> as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.login(req, res, next)

			expect(authService.login).toHaveBeenCalledWith('x@y.com', 'secret', undefined)
			expect(res.json).toHaveBeenCalledWith({ token: 't' })
		})
	})

	describe('logout', () => {
		it('revokes token from body', async () => {
			;(authService.revokeRefreshToken as jest.Mock).mockResolvedValueOnce(null)

			const req = {
			body: { refreshToken: 'ref-1' },
			header: jest.fn(),
			} as unknown as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.logout(req, res, next)

			expect(authService.revokeRefreshToken).toHaveBeenCalledWith('ref-1')
			expect(res.status).toHaveBeenCalledWith(204)
		})

		it('revokes token from Authorization header', async () => {
			;(authService.revokeRefreshToken as jest.Mock).mockResolvedValueOnce(null)

			const req = {
			body: {},
			header: (name: string) => {
				if (name === 'Authorization') return 'Bearer abc.def'
				return undefined
			},
			} as unknown as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.logout(req, res, next)

			expect(authService.revokeRefreshToken).toHaveBeenCalledWith('abc.def')
			expect(res.status).toHaveBeenCalledWith(204)
		})
	})

	describe('requestPasswordReset / confirmPasswordReset', () => {
		it('calls requestPasswordReset and returns success message', async () => {
			;(authService.requestPasswordReset as jest.Mock).mockResolvedValueOnce(null)

			const req = { body: { email: 'a@b.com' } } as Partial<Request> as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.requestPasswordReset(req, res, next)

			expect(authService.requestPasswordReset).toHaveBeenCalledWith('a@b.com')
			expect(res.json).toHaveBeenCalledWith({ message: 'If that email exists, we sent a reset code' })
		})

		it('confirms reset and returns message', async () => {
			;(authService.confirmPasswordReset as jest.Mock).mockResolvedValueOnce(null)

			const req = {
			body: { email: 'a@b.com', code: '123', newPassword: 'newpass' },
			} as Partial<Request> as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.confirmPasswordReset(req, res, next)

			expect(authService.confirmPasswordReset).toHaveBeenCalledWith('a@b.com', '123', 'newpass')
			expect(res.json).toHaveBeenCalledWith({ message: 'Password reset successful' })
		})
	})

	describe('me', () => {
		it('returns req.user', async () => {
			const user = { id: 'u1', email: 'me@me' }
			const req = { user } as unknown as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.me(req, res, next)

			expect(res.json).toHaveBeenCalledWith(user)
		})
	})
})
