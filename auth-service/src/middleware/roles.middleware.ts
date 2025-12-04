import { Request, Response, NextFunction } from 'express'
import logger from '../utils/logger'

export const requireRoles = (allowed: string[]) => (req: Request, res: Response, next: NextFunction) => {
    if(!req.user) {
        logger.warn('Authorization failed: user not authenticated', {
            method: req.method,
            path: req.path
        })
        return res.status(401).json({message: 'Unauthorized'})
    }
    if(!allowed.includes(req.user.role)) {
        logger.warn('Authorization failed: insufficient permissions', {
            userId: req.user.id,
            userRole: req.user.role,
            requiredRoles: allowed,
            method: req.method,
            path: req.path
        })
        return res.status(403).json({message: 'Forbidden'})
    }
    logger.debug('Authorization successful', {
        userId: req.user.id,
        role: req.user.role,
        method: req.method,
        path: req.path
    })
    return next()
}