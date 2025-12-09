import { Request, Response, NextFunction } from 'express'
import { validateToken } from '../services/auth.client'
import logger from '../utils/logger'

export interface AuthenticatedRequest extends Request {
	user?: {
		id: string
		email: string
		role: string
		name: string
	}
}

export const authenticate = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
	try {
		const authHeader = req.header('Authorization')

		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			logger.warn('Authentication failed: missing or invalid auth header', {
				method: req.method,
				path: req.path,
				ip: req.ip
			})
			return res.status(401).json({ message: 'No token provided' })
		}

		const token = authHeader.split(' ')[1]
		if (!token) {
			logger.warn('Authentication failed: token missing', {
				method: req.method,
				path: req.path,
				ip: req.ip
			})
			return res.status(401).json({ message: 'Token missing' })
		}
		const user = await validateToken(token!)

		logger.debug('Authentication successful', {
			userId: user.id,
			email: user.email,
			role: user.role,
			method: req.method,
			path: req.path
		})

		req.user = user
		next()
		return
	} catch (error: any) {
		logger.warn('Authentication failed', {
			method: req.method,
			path: req.path,
			error: error.message,
			ip: req.ip
		})
		return res.status(error.status || 401).json({ message: error.message || 'Authentication failed' })
	}
}
