import prisma from '../prisma/client.prisma'
import { hashPassword, comparePassword } from '../utils/hash'
import { generateAccessToken, generateRefreshToken, verifyToken } from '../utils/jwt'
import { sendMail } from '../utils/mailer'
import crypto from 'crypto'
import { compare } from 'bcryptjs'

const REFRESH_TOKEN_EXPIRES_DAYS = 7
const INVITE_EXPIRES_HOURS = 72
const OTP_EXPIRES_MINUTES = 15

const allowedInvites: Record<string, string[]> = {
    SUPER_ADMIN: ['SITE_ADMIN', 'OPERATOR', 'CLIENT_ADMIN'],
    SITE_ADMIN: ['OPERATOR', 'CLIENT_ADMIN'],
    OPERATOR: ['CLIENT_ADMIN']
}

export const createInvitation = async (inviterId: string, email: string, role: string) => {
    const inviter = await prisma.user.findUnique({where: {id: inviterId}})
    if(!inviter) throw {status: 404, message: 'Inviter not found'}
    const allowed = allowedInvites[inviter.role]
    if(!allowed || !allowed.includes(role)) throw {status: 403, message: 'Not allowed to invite this role'}

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

export const registerWithInvitation = async (token: string, name: string, password: string, phone?: string) => {
    const invite = await prisma.invitation.findUnique({where: {token}})
    if(!invite) throw {status: 400, message: 'Invalid invitation token'}
    if(invite.used) throw {status: 400, message: 'Invitation already used'}
    if(invite.expiresAt < new Date()) throw {status: 400, message: 'Invitation expired'}

    const existing = await prisma.user.findUnique({where: {email: invite.email}})
    if (existing) throw {status: 400, message: 'User with this email already exists'}

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

    await prisma.invitation.update({where: {id: invite.id}, data: {used: true}})

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
        user: {
            id: user.id,
            email: user.email,
            role: user.role
        }, accessToken, refreshToken: refreshJwt
    }
}

export const login = async (email: string, password: string) => {
    const user = await prisma.user.findUnique({where: {email}})
    if (!user) throw { status: 400, message: 'Invalid credentials' }

    const ok = await comparePassword(password, user.password)
    if (!ok) throw { status: 400, message: 'Invalid credentials' }

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

    const code = Math.floor(100000 + Math.random() * 900000).toString() // 6 digits
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