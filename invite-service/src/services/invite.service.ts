import prisma from '../prisma/client.prisma'
import { sendMail } from '../utils/mailer'
import crypto from 'crypto'

const INVITE_EXPIRES_HOURS = 72

const allowedInvites: Record<string, string[]> = {
	'SUPER_ADMIN': ['SITE_ADMIN', 'OPERATOR', 'CLIENT_ADMIN'],
	'SITE_ADMIN': ['OPERATOR', 'CLIENT_ADMIN'],
	'OPERATOR': ['CLIENT_ADMIN']
}

export const createInvitation = async (inviterId: string, email: string, role: string) => {
  // Get inviter details from auth service (could be cached)
	const inviter = await prisma.user.findUnique({ where: { id: inviterId } })
	if (!inviter) {
		throw { status: 404, message: 'Inviter not found' }
	}

	const allowed = allowedInvites[inviter.role]
	if (!allowed || !allowed.includes(role)) {
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

	return invite
}

export const verifyInvitation = async (token: string) => {
	const invite = await prisma.invitation.findUnique({ where: { token } })

	if (!invite) {
		throw { status: 400, message: 'Invalid invitation token' }
	}

	if (invite.used) {
		throw { status: 400, message: 'Invitation already used' }
	}

	if (invite.expiresAt < new Date()) {
		throw { status: 400, message: 'Invitation expired' }
	}

	return invite
}

export const markInvitationAsUsed = async (inviteId: string) => {
	await prisma.invitation.update({
		where: { id: inviteId },
		data: { used: true }
	})
}

export const getInvitationsByUser = async (userId: string) => {
	return await prisma.invitation.findMany({
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
}
