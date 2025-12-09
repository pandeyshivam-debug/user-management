import { Response, NextFunction } from 'express'
import { AuthenticatedRequest } from './auth.middleware'
import logger from '../utils/logger'

export const requireRoles = (allowed: string[]) => (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
	if (!req.user) {
		logger.warn('Role check failed: user not authenticated', {
			method: req.method,
			path: req.path,
			ip: req.ip
		})
		return res.status(401).json({ message: 'Unauthorized' })
	}

	if (!allowed.includes(req.user.role)) {
		logger.warn('Role check failed: insufficient permissions', {
			userId: req.user.id,
			userRole: req.user.role,
			requiredRoles: allowed,
			method: req.method,
			path: req.path
		})
		return res.status(403).json({ message: 'Forbidden' })
	}

	logger.debug('Role check passed', {
		userId: req.user.id,
		userRole: req.user.role,
		method: req.method,
		path: req.path
	})

	return next()
}
