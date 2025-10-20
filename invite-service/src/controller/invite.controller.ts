import { Response, NextFunction } from "express"
import { AuthenticatedRequest } from '../middleware/auth.middleware'
import * as inviteService from '../services/invite.service'
import { z } from 'zod'

const inviteSchema = z.object({
	email: z.email(),
	role: z.enum(['SUPER_ADMIN', 'SITE_ADMIN', 'OPERATOR', 'CLIENT_ADMIN', 'CLIENT_USER'])
})

const verifyInviteSchema = z.object({
	token: z.string()
})

export const createInvite = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
	try {
		const parsed = inviteSchema.parse(req.body)
		const invite = await inviteService.createInvitation(req.user!.id, parsed.email, parsed.role)

		res.json({ 
			invite: { 
			id: invite.id, 
			email: invite.email, 
			role: invite.role, 
			expiresAt: invite.expiresAt 
			} 
		})
	} catch (err) {
		next(err)
	}
}

export const verifyInvite = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
	try {
		const parsed = verifyInviteSchema.parse(req.body)
		const invite = await inviteService.verifyInvitation(parsed.token)

		res.json({ 
			invite: { 
			id: invite.id, 
			email: invite.email, 
			role: invite.role, 
			expiresAt: invite.expiresAt 
			} 
		})
	} catch (err) {
		next(err)
	}
}

export const getMyInvites = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
	try {
		const invites = await inviteService.getInvitationsByUser(req.user!.id)
		res.json({ invites })
	} catch (err) {
		next(err)
	}
}
