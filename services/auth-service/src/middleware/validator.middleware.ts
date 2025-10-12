import { z } from 'zod'

export const inviteSchema = z.object({
    email: z.email(),
    role: z.enum(['SITE_ADMIN', 'OPERATOR', 'CLIENT_ADMIN', 'CLIENT_USER', 'SUPER_ADMIN'])
})

export const registerSchema = z.object({
    token: z.string(),
    name: z.string().min(1),
    password: z.string().min(8),
    phone: z.string().optional()
})

export const loginSchema = z.object({
    email: z.email(),
    password: z.string().min(1),
    totp: z.string().optional()
})

export const refreshSchema = z.object({
    refreshToken: z.string()
})

export const requestResetSchema = z.object({
    email: z.email()
})

export const confirmResetSchema = z.object({
    email: z.email(),
    code: z.string(),
    newPassword: z.string().min(8)
})

export const requestOTPSchema = z.object({ email: z.string().email() })
export const verifyOTPSchema = z.object({ email: z.string().email(), code: z.string() })