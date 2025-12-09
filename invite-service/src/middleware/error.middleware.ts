import { Request, Response, NextFunction } from 'express'
import logger from '../utils/logger'

export const errorHandler = (err: any, req: Request, res: Response, next: NextFunction) => {
    const status = err.status || 500
    logger.error('Request error', {
        status,
        message: err.message || 'Internal server error',
        method: req.method,
        path: req.path,
        ip: req.ip,
        stack: err.stack
    })
    res.status(status).json({message: err.message || 'Internal server error'})
}