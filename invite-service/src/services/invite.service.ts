import prisma from '../prisma/client.prisma'
import { sendMail } from '../utils/mailer'
import crypto from 'crypto'
import logger from '../utils/logger'

const INVITE_EXPIRES_HOURS = 72

const allowedInvites: Record<string, string[]> = {
	'SUPER_ADMIN': ['SITE_ADMIN', 'OPERATOR', 'CLIENT_ADMIN'],
	'SITE_ADMIN': ['OPERATOR', 'CLIENT_ADMIN'],
	'OPERATOR': ['CLIENT_ADMIN'],
	'CLIENT_ADMIN': ['CLIENT_USER']
}

export const createInvitation = async (inviterId: string, email: string, role: string) => {
	const existing = await prisma.user.findUnique({where: {email: email}})
	if (existing) {
		logger.warn('Seeding failed: SUPER_ADMIN already exists', { email: email })
		throw { status: 400, message: 'User with this email already exixts' }
	}

	logger.debug('Creating invitation', { inviterId, email, role })
	const inviter = await prisma.user.findUnique({ where: { id: inviterId } })
	if (!inviter) {
		logger.warn('Invitation creation failed: inviter not found', { inviterId })
		throw { status: 404, message: 'Inviter not found' }
	}
	const allowed = allowedInvites[inviter.role]
	if (!allowed || !allowed.includes(role)) {
		logger.warn('Invitation creation failed: role not allowed', { inviterId, inviterRole: inviter.role, requestedRole: role })
		throw { status: 403, message: 'Not allowed to invite this role' }
	}

	const token = crypto.randomBytes(24).toString('hex')
	const expiresAt = new Date(Date.now() + INVITE_EXPIRES_HOURS * 60 * 60 * 1000)

	const invite = await prisma.invitation.create({
	data: {
		email,
		invitedBy: inviterId,
		role: role as any,
		token,
		expiresAt
	}
	})

	const link = `http://localhost:3000/register?token=${token}`
	await sendMail(
		email,
		'You are invited',
		`You have been invited. Register using this link: ${link}`,
		`<p>You have been invited. Register using this link: <a href="${link}">${link}</a></p>`
	)
	logger.info('Invitation created and email sent', { inviteId: invite.id, email, role, inviterId, token: token.substring(0, 8) + '...' })

	return invite
}

export const verifyInvitation = async (token: string) => {
	logger.debug('Verifying invitation', { token: token.substring(0, 8) + '...' })
	const invite = await prisma.invitation.findUnique({ where: { token } })

	if (!invite) {
		logger.warn('Invitation verification failed: invalid token', { token: token.substring(0, 8) + '...' })
		throw { status: 400, message: 'Invalid invitation token' }
	}

	if (invite.used) {
		logger.warn('Invitation verification failed: already used', { inviteId: invite.id, email: invite.email })
		throw { status: 400, message: 'Invitation already used' }
	}

	if (invite.expiresAt < new Date()) {
		logger.warn('Invitation verification failed: expired', { inviteId: invite.id, email: invite.email, expiresAt: invite.expiresAt })
		throw { status: 400, message: 'Invitation expired' }
	}

	logger.debug('Invitation verified successfully', { inviteId: invite.id, email: invite.email, role: invite.role })
	return invite
}

export const markInvitationAsUsed = async (inviteId: string) => {
	logger.debug('Marking invitation as used', { inviteId })
	await prisma.invitation.update({
		where: { id: inviteId },
		data: { used: true }
	})
	logger.info('Invitation marked as used', { inviteId })
}

export const getInvitationsByUser = async (userId: string) => {
	logger.debug('Fetching invitations by user', { userId })
	const invites = await prisma.invitation.findMany({
	where: { invitedBy: userId },
	select: {
		id: true,
		email: true,
		role: true,
		used: true,
		expiresAt: true,
		createdAt: true
	},
	orderBy: { createdAt: 'desc' }
	})
	logger.debug('Invitations retrieved', { userId, count: invites.length })
	return invites
}
