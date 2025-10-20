import { Request, Response, NextFunction } from 'express'
import { validateToken } from '../services/auth.client'

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
			return res.status(401).json({ message: 'No token provided' })
		}

		const token = authHeader.split(' ')[1]
		if (!token) {
			return res.status(401).json({ message: 'Token missing' })
		}
		const user = await validateToken(token!)

		req.user = user
		next()
		return
	} catch (error: any) {
		return res.status(error.status || 401).json({ message: error.message || 'Authentication failed' })
	}
}
