import { Request, Response, NextFunction } from "express"
import * as authService from '../services/auth.service'
import logger from '../utils/logger'

export const validateToken = async (req: Request, res: Response, next: NextFunction) => {
	logger.info('Token validation request received', { ip: req.ip })
	try {
		const { token } = req.body
		const user = await authService.validateAccessToken(token)
		logger.info('Token validated successfully', { userId: user.id, email: user.email })
		res.json({ user })
	} catch (err: any) {
		logger.warn('Token validation failed', { error: err.message, ip: req.ip })
		next(err)
	}
}

export const getUserById = async (req: Request, res: Response, next: NextFunction) => {
	logger.info('Get user by ID request received', { requestedUserId: req.params.userId, ip: req.ip })
	try {
		const { userId } = req.params
		const user = await authService.getUserById(userId!)
		logger.info('User retrieved successfully', { userId: user.id, email: user.email })
		res.json({ user })
	} catch (err: any) {
		logger.warn('Failed to retrieve user', { requestedUserId: req.params.userId, error: err.message })
		next(err)
	}
}
