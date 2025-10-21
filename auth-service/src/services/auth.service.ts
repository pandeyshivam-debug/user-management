import prisma from '../prisma/client.prisma'
import { hashPassword, comparePassword } from '../utils/hash'
import crypto from 'crypto'
import { compare } from 'bcryptjs'
import axios from 'axios'

import { generateAccessToken, generateRefreshToken, verifyToken } from '../utils/jwt'
import { generateTOTPSecret, verifyTOTP } from '../utils/totp'
import { sendMail } from '../utils/mailer'

const REFRESH_TOKEN_EXPIRES_DAYS = 7
const OTP_EXPIRES_MINUTES = 15

const INVITE_SERVICE_URL: string = process.env.INVITE_SERVICE_URL ?? 'http://localhost:3002/api/v1/invites'

export const registerWithInvitation = async (invite: any, name: string, password: string, phone?: string) => {
	const existing = await prisma.user.findUnique({ where: { email: invite.email } })
	if (existing) throw { status: 400, message: 'User with this email already exists' }

	const hashed = await hashPassword(password)
	const user = await prisma.user.create({
	data: {
		email: invite.email,
		name,
		password: hashed,
		phone: phone ?? null,
		role: invite.role,
		isVerified: true
	}
	})

	// Mark invitation as used via invite service
	await axios.post(`${INVITE_SERVICE_URL}/api/v1/invites/mark-used`, {
		inviteId: invite.id
	})

	const tokenId = crypto.randomUUID()
	const refreshJwt = generateRefreshToken(user.id, tokenId)
	const tokenHash = await hashPassword(refreshJwt)
	const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000)

	await prisma.refreshToken.create({
	data: {
		id: tokenId,
		userId: user.id,
		tokenHash,
		expiresAt
	}
	})

	const accessToken = generateAccessToken(user.id)
	return {
		user: { id: user.id, email: user.email, role: user.role },
		accessToken,
		refreshToken: refreshJwt
	}
}

export const login = async (email: string, password: string, totp?: string) => {
    const user = await prisma.user.findUnique({where: {email}})
    if (!user) throw { status: 400, message: 'Invalid credentials' }

    const ok = await comparePassword(password, user.password)
    if (!ok) throw { status: 400, message: 'Invalid credentials' }

    if(user.totpSecret) {
        if(!totp) throw { status: 400, message: 'TOTP required' }
        const validTotp = verifyTOTP(user.totpSecret, totp)
        if(!validTotp) throw { status: 400, message: 'Invalid TOTP' }
    }

    const accessToken = generateAccessToken(user.id)

    const tokenId = crypto.randomUUID()
    const refreshJwt = generateRefreshToken(user.id, tokenId)
    const tokenHash = await hashPassword(refreshJwt)
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000)

    await prisma.refreshToken.create({
        data: {
            id: tokenId,
            userId: user.id,
            tokenHash,
            expiresAt
        }
    })

    return { accessToken, refreshToken: refreshJwt }
}

export const enable2FA = async (userId: string) => {
    const user = await prisma.user.findUnique({ where: { id: userId } })
    if(!user) throw { status: 404, message: 'User not found' }

    const secret = generateTOTPSecret(user.email)
    await prisma.user.update({ where: { id: userId }, data: { totpSecret: secret.base32 } })

    return { message: 'TOTP 2FA enabled', secret: secret.base32, otpauthUrl: secret.otpauth_url }
}

export const rotateRefreshToken = async (incomingRefreshToken: string) => {
    const payload = verifyToken(incomingRefreshToken)
    if(!payload || !payload.userId || !payload.tokenId) throw {status: 401, message: 'Invalid refresh token'}

    const tokenId = payload.tokenId as string
    const record = await prisma.refreshToken.findUnique({ where: { id: tokenId } })
    if (!record || record.revoked) throw {status: 401, message: 'Refresh token invalid'}
    if (record.expiresAt < new Date()) throw {status: 401, message: 'Refresh token expired'}

    const match = await compare(incomingRefreshToken, record.tokenHash)
    if (!match) throw {status: 401, message: 'Refresh token mismatch'}

    const newTokenId = crypto.randomUUID()
    const newRefreshJwt = generateRefreshToken(record.userId, newTokenId)
    const newTokenHash = await hashPassword(newRefreshJwt)
    const newExpires = new Date(Date.now() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000)

    await prisma.$transaction([
        prisma.refreshToken.update({
            where: {id: tokenId},
            data: {revoked: true, replacedById: newTokenId}
        }),
        prisma.refreshToken.create({
            data: {
                id: newTokenId,
                userId: record.userId,
                tokenHash: newTokenHash,
                expiresAt: newExpires
            }
        })
    ])
    const user = await prisma.user.findUnique({ where: { id: record.userId } })
    if (!user) throw { status: 500, message: 'User missing' }

    const accessToken = generateAccessToken(user.id)
    return { accessToken, refreshToken: newRefreshJwt }
}

export const revokeRefreshToken = async (incomingRefreshToken: string) => {
    const payload = verifyToken(incomingRefreshToken)
    if (!payload || !payload.tokenId) return
    const tokenId = payload.tokenId as string
    await prisma.refreshToken.updateMany({where: { id: tokenId }, data: { revoked: true }})
}

export const requestPasswordReset = async (email: string) => {
    const user = await prisma.user.findUnique({ where: { email } })
    if (!user) return // don't reveal user existence

    const code = Math.floor(100000 + Math.random() * 900000).toString()
    const expiresAt = new Date(Date.now() + OTP_EXPIRES_MINUTES * 60 * 1000)

    await prisma.otp.create({
        data: {
            userId: user.id,
            code,
            type: 'PASSWORD_RESET',
            expiresAt
        }
    })

    await sendMail(user.email, 'Password reset code', `Your password reset code is ${code}`)
}

export const confirmPasswordReset = async (email: string, code: string, newPassword: string) => {
    const user = await prisma.user.findUnique({ where: { email } })
    if (!user) throw { status: 400, message: 'Invalid request' }

    const otp = await prisma.otp.findFirst({
        where: { userId: user.id, code, type: 'PASSWORD_RESET', used: false },
        orderBy: { createdAt: 'desc' },
    })
    if (!otp) throw { status: 400, message: 'Invalid or expired code' }
    if (otp.expiresAt < new Date()) throw { status: 400, message: 'Code expired' }

    const hashed = await hashPassword(newPassword)
    await prisma.user.update({ where: { id: user.id }, data: { password: hashed } })
    await prisma.otp.update({ where: { id: otp.id }, data: { used: true } })
}

export const requestLoginOTP = async (email: string) => {
    const user = await prisma.user.findUnique({ where: { email } })
    if(!user) return

    const code = Math.floor(100000 + Math.random() * 900000).toString()
    const expiresAt = new Date(Date.now() + OTP_EXPIRES_MINUTES * 60 * 1000)

    await prisma.otp.create({ data: { userId: user.id, code, type: 'LOGIN', expiresAt } })
    await sendMail(user.email, 'Login OTP', `Your login code is ${code}`)
}

export const verifyLoginOTP = async (email: string, code: string) => {
    const user = await prisma.user.findUnique({ where: { email } })
    if(!user) throw { status: 400, message: 'Invalid OTP' }

    const otp = await prisma.otp.findFirst({
        where: { userId: user.id, code, type: 'LOGIN', used: false },
        orderBy: { createdAt: 'desc' }
    })
    if(!otp || otp.expiresAt < new Date()) throw { status: 400, message: 'Invalid or expired OTP' }

    await prisma.otp.update({ where: { id: otp.id }, data: { used: true } })

    const accessToken = generateAccessToken(user.id)
    const tokenId = crypto.randomUUID()
    const refreshJwt = generateRefreshToken(user.id, tokenId)
    const tokenHash = await hashPassword(refreshJwt)
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000)

    await prisma.refreshToken.create({ data: { id: tokenId, userId: user.id, tokenHash, expiresAt } })

    return { accessToken, refreshToken: refreshJwt }
}

export const verify2FA = async (userId: string, code: string) => {
    const user = await prisma.user.findUnique({ where: { id: userId } })
    if (!user || !user.totpSecret) throw { status: 400, message: '2FA not enabled' }

    const isValid = verifyTOTP(user.totpSecret, code)
    if (!isValid) throw { status: 400, message: 'Invalid TOTP code' }

    return { message: '2FA code verified successfully' }
}

export const validateAccessToken = async (token: string) => {
	const payload = verifyToken(token)
	if (!payload || !payload.userId) {
		throw { status: 401, message: 'Invalid token' }
	}

	const user = await prisma.user.findUnique({
	where: { id: payload.userId },
		select: { id: true, email: true, role: true, name: true }
	})

	if (!user) {
		throw { status: 401, message: 'User not found' }
	}

	return user
}

export const getUserById = async (userId: string) => {
	const user = await prisma.user.findUnique({
		where: { id: userId },
		select: { id: true, email: true, role: true, name: true }
	})

	if (!user) {
		throw { status: 404, message: 'User not found' }
	}

	return user
}
