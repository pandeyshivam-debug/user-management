import { Request, Response, NextFunction } from "express"
import * as authService from '../services/auth.service'

export const validateToken = async (req: Request, res: Response, next: NextFunction) => {
	try {
		const { token } = req.body
		const user = await authService.validateAccessToken(token)
		res.json({ user })
	} catch (err) {
		next(err)
	}
}

export const getUserById = async (req: Request, res: Response, next: NextFunction) => {
	try {
		const { userId } = req.params
		const user = await authService.getUserById(userId!)
		res.json({ user })
	} catch (err) {
		next(err)
	}
}
