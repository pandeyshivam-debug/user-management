import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

export const connectDatabase = async () => {
    try {
        await prisma.$connect()
        console.log('MongoDB connected successfully')
    } catch (error) {
        console.error('MongoDB connection error:', error)
    }
}

export const disconnectDatabase = async () => {
    await prisma.$disconnect()
}

export default prisma
