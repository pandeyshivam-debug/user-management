import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt';
import prisma from '../prisma/client.prisma'
import logger from '../utils/logger'

export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
    const auth = req.header('Authorization')
    if(!auth || !auth.startsWith('Bearer')) {
        logger.warn('Authentication failed: missing or invalid auth header', {
            method: req.method,
            path: req.path,
            ip: req.ip
        })
        return res.status(401).json({message: 'Unauthorized'})
    }

    const token = auth.split(' ')[1]!
    const payload = verifyToken(token)

    if(!payload || !payload.userId) {
        logger.warn('Authentication failed: invalid or expired token', {
            method: req.method,
            path: req.path,
            ip: req.ip
        })
        return res.status(401).json({message: 'Invalid or expired token'})
    }
    
    const user = await prisma.user.findUnique({where: {id: payload.userId}})
    if(!user) {
        logger.warn('Authentication failed: user not found', {
            userId: payload.userId,
            method: req.method,
            path: req.path
        })
        return res.status(401).json({message: 'User not found'})
    }

    logger.debug('Authentication successful', {
        userId: user.id,
        email: user.email,
        role: user.role,
        method: req.method,
        path: req.path
    })

    req.user = { id: user.id, role: user.role, email: user.email}
    return next()
}