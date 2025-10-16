import { Request, Response, NextFunction } from "express"
import * as authService from '../services/auth.service'
import {
    inviteSchema,
    registerSchema,
    loginSchema,
    refreshSchema,
    requestResetSchema,
    confirmResetSchema,
    requestOTPSchema,
    verifyOTPSchema
} from '../middleware/validator.middleware'

export const invite = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const parsed = inviteSchema.parse(req.body)
        const invite = await authService.createInvitation(req.user!.id, parsed.email, parsed.role)
        res.json({ invite: { id: invite.id, email: invite.email, role: invite.role, expiresAt: invite.expiresAt } })
    } catch (err) {
        next(err)
    }
}

export const register = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const parsed = registerSchema.parse(req.body)
        const result = await authService.registerWithInvitation(parsed.token, parsed.name, parsed.password, parsed.phone)
        res.json(result)
    } catch (err) {
        next(err)
    }
}

export const login = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const parsed = loginSchema.parse(req.body)
        const result = await authService.login(parsed.email, parsed.password, parsed.totp)
        res.json(result)
    } catch (err) {
        next(err)
    }
}

export const enable2FA = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const result = await authService.enable2FA(req.user!.id)
        res.json(result)
    } catch (err) {
        next(err)
    }
}

export const verify2FA = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { code } = req.body
        const result = await authService.verify2FA(req.user!.id, code)
        res.json(result)
    } catch (err) {
        next(err)
    }
}


export const refresh = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const parsed = refreshSchema.parse(req.body)
        const result = await authService.rotateRefreshToken(parsed.refreshToken)
        res.json(result)
    } catch (err) {
        next(err)
    }
}

export const logout = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.header('Authorization')
        const bodyToken = (req.body && (req.body.refreshToken as string)) || null
        const token = bodyToken ?? (authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null)
        if (token) await authService.revokeRefreshToken(token)
        res.status(204).send()
    } catch (err) {
        next(err)
    }
}

export const requestPasswordReset = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const parsed = requestResetSchema.parse(req.body)
        await authService.requestPasswordReset(parsed.email)
        res.json({ message: 'If that email exists, we sent a reset code' })
    } catch (err) {
        next(err)
    }
}

export const confirmPasswordReset = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const parsed = confirmResetSchema.parse(req.body)
        await authService.confirmPasswordReset(parsed.email, parsed.code, parsed.newPassword)
        res.json({ message: 'Password reset successful' })
    } catch (err) {
        next(err)
    }
}

export const requestOTP = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const parsed = requestOTPSchema.parse(req.body)
        await authService.requestLoginOTP(parsed.email)
        res.json({ message: 'If that email exists, we sent an OTP' })
    } catch (err) {
        next(err)
    }
}

export const verifyOTP = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const parsed = verifyOTPSchema.parse(req.body)
        const result = await authService.verifyLoginOTP(parsed.email, parsed.code)
        res.json(result)
    } catch (err) {
        next(err)
    }
}

export const me = async (req: Request, res: Response, next: NextFunction) => {
    try {
        res.json(req.user)
    } catch (err) {
        next(err)
    }
}