import prisma from '../prisma/client.prisma'
import { hashPassword, comparePassword } from '../utils/hash'
import crypto from 'crypto'
import { compare } from 'bcryptjs'
import axios from 'axios'
import logger from '../utils/logger'

import { generateAccessToken, generateRefreshToken, verifyToken } from '../utils/jwt'
import { generateTOTPSecret, verifyTOTP } from '../utils/totp'
import { sendMail } from '../utils/mailer'

const REFRESH_TOKEN_EXPIRES_DAYS = 7
const OTP_EXPIRES_MINUTES = 15

const INVITE_SERVICE_URL: string = process.env.INVITE_SERVICE_URL ?? 'http://localhost:3002/api/v1/invites'

export const seedSuperAdmin = async() => {
    const superAdminEmail = "super@admin.com"
    logger.debug('Checking for existing user', { email: superAdminEmail })
	const existing = await prisma.user.findUnique({ where: { email: superAdminEmail } })
	if (existing) {
		logger.warn('Seeding failed: SUPER_ADMIN already exists', { email: superAdminEmail })
		throw { status: 400, message: 'SUPER_ADMIN already seeded in DB' }
	}

    logger.info('Seeding super admin user')
    const hashed = await hashPassword("adminadmin")
    const user = await prisma.user.create({
        data: {
            email: superAdminEmail,
            name: "User One",
            password: hashed,
            role: 'SUPER_ADMIN'
        }
    })
    logger.debug('Super admin user created', { userId: user.id, email: user.email })
    
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
	logger.info('Super admin seeded with tokens', { userId: user.id, tokenId })
	return {
		user: { id: user.id, email: user.email, role: user.role },
		accessToken,
		refreshToken: refreshJwt
	}
}

export const registerWithInvitation = async (invite: any, name: string, password: string, phone?: string) => {
	logger.debug('Checking for existing user', { email: invite.email })
	const existing = await prisma.user.findUnique({ where: { email: invite.email } })
	if (existing) {
		logger.warn('Registration failed: user already exists', { email: invite.email })
		throw { status: 400, message: 'User with this email already exists' }
	}

	logger.debug('Creating new user', { email: invite.email, role: invite.role })
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
	logger.info('User created successfully', { userId: user.id, email: user.email, role: user.role })

	// Mark invitation as used via invite service
	logger.debug('Marking invitation as used', { inviteId: invite.id })
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
	logger.debug('Tokens generated for new user', { userId: user.id, tokenId })
	return {
		user: { id: user.id, email: user.email, role: user.role },
		accessToken,
		refreshToken: refreshJwt
	}
}

export const login = async (email: string, password: string, totp?: string) => {
    logger.debug('Attempting login', { email })
    const user = await prisma.user.findUnique({where: {email}})
    if (!user) {
        logger.warn('Login failed: user not found', { email })
        throw { status: 400, message: 'Invalid credentials' }
    }

    const ok = await comparePassword(password, user.password)
    if (!ok) {
        logger.warn('Login failed: invalid password', { email, userId: user.id })
        throw { status: 400, message: 'Invalid credentials' }
    }

    if (user.totpSecret) {
        logger.debug('2FA required for login', { userId: user.id })
        const tempToken = crypto.randomUUID()
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000)

        await prisma.otp.create({
            data: {
            userId: user.id,
            code: tempToken,
            type: '2FA_TEMP',
            expiresAt,
            },
        })

        logger.debug('2FA temp token created', { userId: user.id, tempToken: tempToken.substring(0, 8) + '...' })
        return { twoFactorRequired: true, tempToken }
    }

    logger.debug('Generating tokens for login', { userId: user.id })
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

    logger.debug('Login tokens created', { userId: user.id, tokenId })
    return { accessToken, refreshToken: refreshJwt }
}

export const verifyLogin2FA = async (tempToken: string, code: string) => {
    logger.debug('Verifying 2FA login', { tempToken: tempToken.substring(0, 8) + '...' })
    const temp = await prisma.otp.findFirst({
        where: { code: tempToken, type: '2FA_TEMP', used: false },
    })
    if (!temp || temp.expiresAt < new Date()) {
        logger.warn('2FA verification failed: invalid or expired temp token', { tempToken: tempToken.substring(0, 8) + '...' })
        throw { status: 400, message: 'Invalid or expired session' }
    }

    const user = await prisma.user.findUnique({ where: { id: temp.userId } })
    if (!user || !user.totpSecret) {
        logger.warn('2FA verification failed: user not found or 2FA not enabled', { userId: temp.userId })
        throw { status: 400, message: 'Invalid user or 2FA not enabled' }
    }

    const valid = verifyTOTP(user.totpSecret, code)
    if (!valid) {
        logger.warn('2FA verification failed: invalid TOTP code', { userId: user.id })
        throw { status: 400, message: 'Invalid TOTP code' }
    }

    await prisma.otp.update({ where: { id: temp.id }, data: { used: true } })
    logger.debug('Generating tokens after 2FA verification', { userId: user.id })
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

    logger.info('2FA login successful', { userId: user.id, tokenId })
    return { accessToken, refreshToken: refreshJwt }
}

export const enable2FA = async (userId: string) => {
    logger.debug('Enabling 2FA', { userId })
    const user = await prisma.user.findUnique({ where: { id: userId } })
    if(!user) {
        logger.warn('Failed to enable 2FA: user not found', { userId })
        throw { status: 404, message: 'User not found' }
    }

    const secret = generateTOTPSecret(user.email)
    await prisma.user.update({ where: { id: userId }, data: { totpSecret: secret.base32 } })
    logger.info('2FA enabled successfully', { userId, email: user.email })

    return { message: 'TOTP 2FA enabled', secret: secret.base32, otpauthUrl: secret.otpauth_url }
}

export const rotateRefreshToken = async (incomingRefreshToken: string) => {
    logger.debug('Rotating refresh token', { token: incomingRefreshToken.substring(0, 8) + '...' })
    const payload = verifyToken(incomingRefreshToken)
    if(!payload || !payload.userId || !payload.tokenId) {
        logger.warn('Token rotation failed: invalid token payload')
        throw {status: 401, message: 'Invalid refresh token'}
    }

    const tokenId = payload.tokenId as string
    const record = await prisma.refreshToken.findUnique({ where: { id: tokenId } })
    if (!record || record.revoked) {
        logger.warn('Token rotation failed: token invalid or revoked', { tokenId, userId: payload.userId })
        throw {status: 401, message: 'Refresh token invalid'}
    }
    if (record.expiresAt < new Date()) {
        logger.warn('Token rotation failed: token expired', { tokenId, userId: payload.userId })
        throw {status: 401, message: 'Refresh token expired'}
    }

    const match = await compare(incomingRefreshToken, record.tokenHash)
    if (!match) {
        logger.warn('Token rotation failed: token mismatch', { tokenId, userId: payload.userId })
        throw {status: 401, message: 'Refresh token mismatch'}
    }

    logger.debug('Creating new refresh token', { userId: record.userId, oldTokenId: tokenId })
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
    if (!user) {
        logger.error('Token rotation failed: user not found', { userId: record.userId })
        throw { status: 500, message: 'User missing' }
    }

    const accessToken = generateAccessToken(user.id)
    logger.info('Token rotated successfully', { userId: user.id, oldTokenId: tokenId, newTokenId })
    return { accessToken, refreshToken: newRefreshJwt }
}

export const revokeRefreshToken = async (incomingRefreshToken: string) => {
    logger.debug('Revoking refresh token', { token: incomingRefreshToken.substring(0, 8) + '...' })
    const payload = verifyToken(incomingRefreshToken)
    if (!payload || !payload.tokenId) {
        logger.warn('Token revocation skipped: invalid token payload')
        return
    }
    const tokenId = payload.tokenId as string
    await prisma.refreshToken.updateMany({where: { id: tokenId }, data: { revoked: true }})
    logger.info('Refresh token revoked', { tokenId, userId: payload.userId })
}

export const requestPasswordReset = async (email: string) => {
    logger.debug('Processing password reset request', { email })
    const user = await prisma.user.findUnique({ where: { email } })
    if (!user) {
        logger.debug('Password reset request: user not found (not revealing)', { email })
        return // don't reveal user existence
    }

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

    logger.info('Password reset code generated and sent', { userId: user.id, email })
    await sendMail(user.email, 'Password reset code', `Your password reset code is ${code}`)
}

export const confirmPasswordReset = async (email: string, code: string, newPassword: string) => {
    logger.debug('Confirming password reset', { email })
    const user = await prisma.user.findUnique({ where: { email } })
    if (!user) {
        logger.warn('Password reset confirmation failed: user not found', { email })
        throw { status: 400, message: 'Invalid request' }
    }

    const otp = await prisma.otp.findFirst({
        where: { userId: user.id, code, type: 'PASSWORD_RESET', used: false },
        orderBy: { createdAt: 'desc' },
    })
    if (!otp) {
        logger.warn('Password reset confirmation failed: invalid code', { userId: user.id })
        throw { status: 400, message: 'Invalid or expired code' }
    }
    if (otp.expiresAt < new Date()) {
        logger.warn('Password reset confirmation failed: code expired', { userId: user.id, otpId: otp.id })
        throw { status: 400, message: 'Code expired' }
    }

    logger.debug('Updating user password', { userId: user.id })
    const hashed = await hashPassword(newPassword)
    await prisma.user.update({ where: { id: user.id }, data: { password: hashed } })
    await prisma.otp.update({ where: { id: otp.id }, data: { used: true } })
    logger.info('Password reset confirmed successfully', { userId: user.id, email })
}

export const requestLoginOTP = async (email: string) => {
    logger.debug('Processing login OTP request', { email })
    const user = await prisma.user.findUnique({ where: { email } })
    if(!user) {
        logger.debug('Login OTP request: user not found (not revealing)', { email })
        return
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString()
    const expiresAt = new Date(Date.now() + OTP_EXPIRES_MINUTES * 60 * 1000)

    await prisma.otp.create({ data: { userId: user.id, code, type: 'LOGIN', expiresAt } })
    logger.info('Login OTP generated and sent', { userId: user.id, email })
    await sendMail(user.email, 'Login OTP', `Your login code is ${code}`)
}

export const verifyLoginOTP = async (email: string, code: string) => {
    logger.debug('Verifying login OTP', { email })
    const user = await prisma.user.findUnique({ where: { email } })
    if(!user) {
        logger.warn('Login OTP verification failed: user not found', { email })
        throw { status: 400, message: 'Invalid OTP' }
    }

    const otp = await prisma.otp.findFirst({
        where: { userId: user.id, code, type: 'LOGIN', used: false },
        orderBy: { createdAt: 'desc' }
    })
    if(!otp || otp.expiresAt < new Date()) {
        logger.warn('Login OTP verification failed: invalid or expired', { userId: user.id })
        throw { status: 400, message: 'Invalid or expired OTP' }
    }

    await prisma.otp.update({ where: { id: otp.id }, data: { used: true } })
    logger.debug('Generating tokens for OTP login', { userId: user.id })

    const accessToken = generateAccessToken(user.id)
    const tokenId = crypto.randomUUID()
    const refreshJwt = generateRefreshToken(user.id, tokenId)
    const tokenHash = await hashPassword(refreshJwt)
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRES_DAYS * 24 * 60 * 60 * 1000)

    await prisma.refreshToken.create({ data: { id: tokenId, userId: user.id, tokenHash, expiresAt } })
    logger.info('Login OTP verified successfully', { userId: user.id, tokenId })

    return { accessToken, refreshToken: refreshJwt }
}

export const verify2FA = async (userId: string, code: string) => {
    logger.debug('Verifying 2FA code', { userId })
    const user = await prisma.user.findUnique({ where: { id: userId } })
    if (!user || !user.totpSecret) {
        logger.warn('2FA verification failed: 2FA not enabled', { userId })
        throw { status: 400, message: '2FA not enabled' }
    }

    const isValid = verifyTOTP(user.totpSecret, code)
    if (!isValid) {
        logger.warn('2FA verification failed: invalid code', { userId })
        throw { status: 400, message: 'Invalid TOTP code' }
    }

    logger.info('2FA code verified successfully', { userId })
    return { message: '2FA code verified successfully' }
}

export const validateAccessToken = async (token: string) => {
	logger.debug('Validating access token', { token: token.substring(0, 8) + '...' })
	const payload = verifyToken(token)
	if (!payload || !payload.userId) {
		logger.warn('Token validation failed: invalid payload')
		throw { status: 401, message: 'Invalid token' }
	}

	const user = await prisma.user.findUnique({
	where: { id: payload.userId },
		select: { id: true, email: true, role: true, name: true }
	})

	if (!user) {
		logger.warn('Token validation failed: user not found', { userId: payload.userId })
		throw { status: 401, message: 'User not found' }
	}

	logger.debug('Token validated successfully', { userId: user.id, email: user.email })
	return user
}

export const getUserById = async (userId: string) => {
	logger.debug('Fetching user by ID', { userId })
	const user = await prisma.user.findUnique({
		where: { id: userId },
		select: { id: true, email: true, role: true, name: true }
	})

	if (!user) {
		logger.warn('User not found', { userId })
		throw { status: 404, message: 'User not found' }
	}

	logger.debug('User retrieved successfully', { userId, email: user.email })
	return user
}
