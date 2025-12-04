import { Request, Response, NextFunction } from "express"
import * as authService from '../services/auth.service'
import logger from "../utils/logger"

import {
    registerSchema,
    loginSchema,
    refreshSchema,
    requestResetSchema,
    confirmResetSchema,
    requestOTPSchema,
    verifyOTPSchema
} from '../middleware/validator.middleware'
import axios from "axios"

const INVITE_SERVICE_URL: string = process.env.INVITE_SERVICE_URL!

export const seedSuperAdmin = async(req: Request, res: Response, next: NextFunction) => {
    logger.info('Seeding super admin user', { ip: req.ip })
    try {
        const result = await authService.seedSuperAdmin()
        logger.info('Super admin seeded successfully', { userId: result.user.id, email: result.user.email })
        res.json(result)
    } catch(err: any) {
        logger.error('Failed to seed super admin', { error: err.message, stack: err.stack })
        next(err)
    }
}

export const register = async (req: Request, res: Response, next: NextFunction) => {
    logger.info('Registration request received', { ip: req.ip })
    try {
        const parsed = registerSchema.parse(req.body)
        logger.debug('Validating invitation token', { token: parsed.token.substring(0, 8) + '...' })
        
        const inviteResponse = await axios.post(`${INVITE_SERVICE_URL}/api/v1/invite/verify`, {
            token: parsed.token
        })
        const invite = inviteResponse.data.invite
        logger.debug('Invitation verified', { inviteId: invite.id, email: invite.email })
        
        const result = await authService.registerWithInvitation(invite, parsed.name, parsed.password, parsed.phone)
        logger.info('User registered successfully', { 
            userId: result.user.id, 
            email: result.user.email, 
            role: result.user.role 
        })
        res.json(result)
    } catch (err: any) {
        logger.error('Registration failed', { 
            error: err.message, 
            email: req.body.email,
            ip: req.ip 
        })
        next(err)
    }
}

export const login = async (req: Request, res: Response, next: NextFunction) => {
    logger.info('Login request received', { email: req.body.email, ip: req.ip })
    try {
        const parsed = loginSchema.parse(req.body)
        const result = await authService.login(parsed.email, parsed.password, parsed.totp)
        
        if (result.twoFactorRequired) {
            logger.info('Login requires 2FA', { email: parsed.email, tempToken: result.tempToken.substring(0, 8) + '...' })
        } else {
            logger.info('Login successful', { email: parsed.email, ip: req.ip })
        }
        res.json(result)
    } catch (err: any) {
        logger.warn('Login failed', { 
            email: req.body.email, 
            error: err.message,
            ip: req.ip 
        })
        next(err)
    }
}

export const verifyLogin2FA = async (req: Request, res: Response, next: NextFunction) => {
    logger.info('2FA verification request received', { ip: req.ip })
    try {
        const { tempToken, code } = req.body
        const result = await authService.verifyLogin2FA(tempToken, code)
        logger.info('2FA verification successful', { 
            tempToken: tempToken.substring(0, 8) + '...',
            ip: req.ip 
        })
        res.json(result)
    } catch (err: any) {
        logger.warn('2FA verification failed', { 
            error: err.message,
            tempToken: req.body.tempToken?.substring(0, 8) + '...',
            ip: req.ip 
        })
        next(err)
    }
}

export const enable2FA = async (req: Request, res: Response, next: NextFunction) => {
    logger.info('2FA enable request received', { userId: req.user!.id })
    try {
        const result = await authService.enable2FA(req.user!.id)
        logger.info('2FA enabled successfully', { userId: req.user!.id, email: req.user!.email })
        res.json(result)
    } catch (err: any) {
        logger.error('Failed to enable 2FA', { userId: req.user!.id, error: err.message })
        next(err)
    }
}

export const verify2FA = async (req: Request, res: Response, next: NextFunction) => {
    logger.info('2FA code verification request received', { userId: req.user!.id })
    try {
        const { code } = req.body
        const result = await authService.verify2FA(req.user!.id, code)
        logger.info('2FA code verified successfully', { userId: req.user!.id })
        res.json(result)
    } catch (err: any) {
        logger.warn('2FA code verification failed', { userId: req.user!.id, error: err.message })
        next(err)
    }
}


export const refresh = async (req: Request, res: Response, next: NextFunction) => {
    logger.info('Refresh token request received', { ip: req.ip })
    try {
        const parsed = refreshSchema.parse(req.body)
        const result = await authService.rotateRefreshToken(parsed.refreshToken)
        logger.info('Token refreshed successfully', { 
            refreshToken: parsed.refreshToken.substring(0, 8) + '...',
            ip: req.ip 
        })
        res.json(result)
    } catch (err: any) {
        logger.warn('Token refresh failed', { error: err.message, ip: req.ip })
        next(err)
    }
}

export const logout = async (req: Request, res: Response, next: NextFunction) => {
    logger.info('Logout request received', { userId: req.user?.id, ip: req.ip })
    try {
        const authHeader = req.header('Authorization')
        const bodyToken = (req.body && (req.body.refreshToken as string)) || null
        const token = bodyToken ?? (authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null)
        if (token) {
            await authService.revokeRefreshToken(token)
            logger.info('Refresh token revoked', { userId: req.user?.id, token: token.substring(0, 8) + '...' })
        }
        logger.info('Logout successful', { userId: req.user?.id })
        res.status(204).send()
    } catch (err: any) {
        logger.error('Logout failed', { userId: req.user?.id, error: err.message })
        next(err)
    }
}

export const requestPasswordReset = async (req: Request, res: Response, next: NextFunction) => {
    logger.info('Password reset request received', { email: req.body.email, ip: req.ip })
    try {
        const parsed = requestResetSchema.parse(req.body)
        await authService.requestPasswordReset(parsed.email)
        logger.info('Password reset code sent', { email: parsed.email })
        res.json({ message: 'If that email exists, we sent a reset code' })
    } catch (err: any) {
        logger.error('Password reset request failed', { email: req.body.email, error: err.message })
        next(err)
    }
}

export const confirmPasswordReset = async (req: Request, res: Response, next: NextFunction) => {
    logger.info('Password reset confirmation received', { email: req.body.email, ip: req.ip })
    try {
        const parsed = confirmResetSchema.parse(req.body)
        await authService.confirmPasswordReset(parsed.email, parsed.code, parsed.newPassword)
        logger.info('Password reset successful', { email: parsed.email })
        res.json({ message: 'Password reset successful' })
    } catch (err: any) {
        logger.warn('Password reset confirmation failed', { email: req.body.email, error: err.message })
        next(err)
    }
}

export const requestOTP = async (req: Request, res: Response, next: NextFunction) => {
    logger.info('OTP request received', { email: req.body.email, ip: req.ip })
    try {
        const parsed = requestOTPSchema.parse(req.body)
        await authService.requestLoginOTP(parsed.email)
        logger.info('Login OTP sent', { email: parsed.email })
        res.json({ message: 'If that email exists, we sent an OTP' })
    } catch (err: any) {
        logger.error('OTP request failed', { email: req.body.email, error: err.message })
        next(err)
    }
}

export const verifyOTP = async (req: Request, res: Response, next: NextFunction) => {
    logger.info('OTP verification request received', { email: req.body.email, ip: req.ip })
    try {
        const parsed = verifyOTPSchema.parse(req.body)
        const result = await authService.verifyLoginOTP(parsed.email, parsed.code)
        logger.info('OTP verification successful', { email: parsed.email })
        res.json(result)
    } catch (err: any) {
        logger.warn('OTP verification failed', { email: req.body.email, error: err.message })
        next(err)
    }
}

export const me = async (req: Request, res: Response, next: NextFunction) => {
    logger.info('User profile request received', { userId: req.user?.id })
    try {
        logger.debug('User profile retrieved', { 
            userId: req.user?.id, 
            email: req.user?.email, 
            role: req.user?.role 
        })
        res.json(req.user)
    } catch (err: any) {
        logger.error('Failed to fetch user profile', { userId: req.user?.id, error: err.message })
        next(err)
    }
}