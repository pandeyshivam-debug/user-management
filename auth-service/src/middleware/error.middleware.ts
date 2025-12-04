import { Request, Response, NextFunction } from 'express'
import logger from '../utils/logger'

export const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
    const status = err.status || 500
    const message = err.message || 'Internal server error'
    
    logger.error('Request error', {
        method: req.method,
        path: req.path,
        status,
        message,
        userId: req.user?.id,
        error: err.stack || err
    })
    
    res.status(status).json({message})
}