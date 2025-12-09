import { Request, Response, NextFunction } from "express"
import { AuthenticatedRequest } from '../middleware/auth.middleware'
import * as inviteService from '../services/invite.service'
import { z } from 'zod'
import logger from '../utils/logger'

const inviteSchema = z.object({
	email: z.email(),
	role: z.enum(['SUPER_ADMIN', 'SITE_ADMIN', 'OPERATOR', 'CLIENT_ADMIN', 'CLIENT_USER'])
})

const verifyInviteSchema = z.object({
	token: z.string()
})

interface MarkUsedBody {
	inviteId: string;
}

export const createInvite = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
	logger.info('Create invite request received', { inviterId: req.user!.id, email: req.body.email, role: req.body.role, ip: req.ip })
	try {
		const parsed = inviteSchema.parse(req.body)
		const invite = await inviteService.createInvitation(req.user!.id, parsed.email, parsed.role)

		logger.info('Invite created successfully', { inviteId: invite.id, email: invite.email, role: invite.role, inviterId: req.user!.id })
		res.json({ 
			invite: { 
			id: invite.id, 
			email: invite.email, 
			role: invite.role, 
			expiresAt: invite.expiresAt 
			} 
		})
	} catch (err: any) {
		logger.warn('Create invite failed', { 
			inviterId: req.user!.id, 
			email: req.body.email, 
			role: req.body.role,
			error: err.message,
			ip: req.ip 
		})
		next(err)
	}
}

export const verifyInvite = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
	logger.info('Verify invite request received', { token: req.body.token?.substring(0, 8) + '...', ip: req.ip })
	try {
		const parsed = verifyInviteSchema.parse(req.body)
		const invite = await inviteService.verifyInvitation(parsed.token)

		logger.info('Invite verified successfully', { inviteId: invite.id, email: invite.email, role: invite.role })
		res.json({ 
			invite: {
				id: invite.id, 
				email: invite.email, 
				role: invite.role, 
				expiresAt: invite.expiresAt 
			} 
		})
	} catch (err: any) {
		logger.warn('Verify invite failed', { 
			token: req.body.token?.substring(0, 8) + '...',
			error: err.message,
			ip: req.ip 
		})
		next(err)
	}
}

export const markUsed = async (req: Request<{}, {}, MarkUsedBody>, res: Response, next: NextFunction) => {
	logger.info('Mark used request received', { inviteId: req.body.inviteId, ip: req.ip })
	try {
		const { inviteId } = req.body

		if (!inviteId) {
			logger.warn('Mark used failed: inviteId missing', { ip: req.ip })
			return res.status(400).json({ message: 'inviteId is required' })
		}

		await inviteService.markInvitationAsUsed(inviteId)

		logger.info('Invitation marked as used successfully', { inviteId })
		return res.status(200).json({ message: 'Invitation marked as used successfully' })
	} catch (error: any) {
		logger.warn('Mark used failed', { 
			inviteId: req.body.inviteId,
			error: error.message,
			ip: req.ip 
		})
		next(error)
		return
	}
}

export const getMyInvites = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
	logger.debug('Get my invites request received', { userId: req.user!.id, ip: req.ip })
	try {
		const invites = await inviteService.getInvitationsByUser(req.user!.id)
		logger.debug('Invites retrieved successfully', { userId: req.user!.id, count: invites.length })
		res.json({ invites })
	} catch (err: any) {
		logger.warn('Get my invites failed', { 
			userId: req.user!.id,
			error: err.message,
			ip: req.ip 
		})
		next(err)
	}
}
