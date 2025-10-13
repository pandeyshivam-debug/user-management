import { Request, Response, NextFunction } from 'express';
import { verifyToken } from '../utils/jwt';
import prisma from '../prisma/client.prisma'

export const authenticate = async (req: Request, res: Response, next: NextFunction) => {
    const auth = req.header('Authorization')
    if(!auth || !auth.startsWith('Bearer')) return res.status(401).json({message: 'Unauthorized'})

    const token = auth.split(' ')[1]!
    const payload = verifyToken(token)

    if(!payload || !payload.userId) return res.status(401).json({message: 'Invalid or expired token'})
    
    const user = await prisma.user.findUnique({where: {id: payload.userId}})
    if(!user) return res.status(401).json({message: 'User not found'})

    req.user = { id: user.id, role: user.role, email: user.email}
    return next()
}