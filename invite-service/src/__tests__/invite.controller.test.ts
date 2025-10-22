import { Request, Response, NextFunction } from 'express'
import * as controller from '../controller/invite.controller'

jest.mock('../services/invite.service', () => ({
	createInvitation: jest.fn(),
	verifyInvitation: jest.fn(),
	markInvitationAsUsed: jest.fn(),
	getInvitationsByUser: jest.fn(),
}))

const inviteService = jest.requireMock('../services/invite.service')

// mock zod validation
jest.mock('zod', () => {
	const actual = jest.requireActual('zod')
	return {
		...actual,
		z: {
			...actual.z,
			object: jest.fn(() => ({
				parse: (v: any) => v,
			})),
			email: jest.fn(() => ({ email: true })),
			enum: jest.fn(() => ({ enum: true })),
			string: jest.fn(() => ({ string: true })),
		},
	}
})

function mockResponse() {
	const res: Partial<Response> = {}
	res.status = jest.fn().mockReturnValue(res)
	res.json = jest.fn().mockReturnValue(res)
	return res as Response
}

function mockNext() {
	return jest.fn() as unknown as NextFunction
}

describe('invite.controller', () => {
	beforeEach(() => {
		jest.clearAllMocks()
	})

	describe('createInvite', () => {
		it('creates an invite and returns response', async () => {
			const invite = {
				id: 'inv1',
				email: 'test@ex.com',
				role: 'CLIENT_USER',
				expiresAt: new Date().toISOString(),
			}

			;(inviteService.createInvitation as jest.Mock).mockResolvedValueOnce(invite)

			const req = {
				body: { email: 'test@ex.com', role: 'CLIENT_USER' },
				user: { id: 'u1' },
			} as any as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.createInvite(req, res, next)

			expect(inviteService.createInvitation).toHaveBeenCalledWith('u1', 'test@ex.com', 'CLIENT_USER')
			expect(res.json).toHaveBeenCalledWith({
				invite: {
					id: invite.id,
					email: invite.email,
					role: invite.role,
					expiresAt: invite.expiresAt,
				},
			})
		})

		it('calls next on error', async () => {
			;(inviteService.createInvitation as jest.Mock).mockRejectedValueOnce(new Error('fail'))

			const req = { body: {}, user: { id: 'u1' } } as any as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.createInvite(req, res, next)
			expect(next).toHaveBeenCalled()
		})
	})

	describe('verifyInvite', () => {
		it('verifies an invite and returns response', async () => {
			const invite = {
				id: 'inv1',
				email: 'a@b.com',
				role: 'OPERATOR',
				expiresAt: new Date().toISOString(),
			}
			;(inviteService.verifyInvitation as jest.Mock).mockResolvedValueOnce(invite)

			const req = { body: { token: 'tok' } } as any as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.verifyInvite(req, res, next)

			expect(inviteService.verifyInvitation).toHaveBeenCalledWith('tok')
			expect(res.json).toHaveBeenCalledWith({
				invite: {
					id: invite.id,
					email: invite.email,
					role: invite.role,
					expiresAt: invite.expiresAt,
				},
			})
		})

		it('passes errors to next if verification fails', async () => {
			;(inviteService.verifyInvitation as jest.Mock).mockRejectedValueOnce(new Error('invalid token'))

			const req = { body: { token: 'bad' } } as any as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.verifyInvite(req, res, next)

			expect(next).toHaveBeenCalled()
		})
	})

	describe('markUsed', () => {
		it('returns 400 if inviteId missing', async () => {
			const req = { body: {} } as any as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.markUsed(req, res, next)

			expect(res.status).toHaveBeenCalledWith(400)
			expect(res.json).toHaveBeenCalledWith({ message: 'inviteId is required' })
		})

		it('marks invitation as used', async () => {
			;(inviteService.markInvitationAsUsed as jest.Mock).mockResolvedValueOnce(null)

			const req = { body: { inviteId: 'i1' } } as any as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.markUsed(req, res, next)

			expect(inviteService.markInvitationAsUsed).toHaveBeenCalledWith('i1')
			expect(res.status).toHaveBeenCalledWith(200)
			expect(res.json).toHaveBeenCalledWith({ message: 'Invitation marked as used successfully' })
		})
	})

	describe('getMyInvites', () => {
		it('returns invites for user', async () => {
			const invites = [{ id: 'inv1' }, { id: 'inv2' }]
			;(inviteService.getInvitationsByUser as jest.Mock).mockResolvedValueOnce(invites)

			const req = { user: { id: 'u1' } } as any as Request
			const res = mockResponse()
			const next = mockNext()

			await controller.getMyInvites(req, res, next)

			expect(inviteService.getInvitationsByUser).toHaveBeenCalledWith('u1')
			expect(res.json).toHaveBeenCalledWith({ invites })
		})
	})
})
