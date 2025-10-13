import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

export const generateOtp = async (userId: string, type: string) => {
    const code = Math.floor(100000 + Math.random() * 900000).toString() 
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000)
    await prisma.otp.create({
        data: {
            userId,
            code,
            type,
            expiresAt
        }
    })
    return code
}

export const verifyOtp = async (userId: string, code: string) => {
    const otp = await prisma.otp.findFirst({
        where: {userId, code, used: false}
    })
    if(!otp || otp.expiresAt < new Date()) return false
    await prisma.otp.update({
        where: { id: otp.id },
        data: { used: true }
    })
    return true
}