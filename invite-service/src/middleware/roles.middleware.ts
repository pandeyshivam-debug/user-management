import { Response, NextFunction } from 'express'
import { AuthenticatedRequest } from './auth.middleware'

export const requireRoles = (allowed: string[]) => (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
	if (!req.user) return res.status(401).json({ message: 'Unauthorized' })

	if (!allowed.includes(req.user.role)) return res.status(403).json({ message: 'Forbidden' })

	return next()
}
