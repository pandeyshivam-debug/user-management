import axios from 'axios'
import logger from '../utils/logger'

const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://localhost:3001'

export interface User {
	id: string
	email: string
	role: string
	name: string
}

export const validateToken = async (token: string): Promise<User> => {
	logger.debug('Validating token with auth service', { token: token.substring(0, 8) + '...' })
	try {
		const response = await axios.post(`${AUTH_SERVICE_URL}/api/v1/internal/validate-token`, {
			token
		})
		logger.debug('Token validated successfully', { userId: response.data.user.id, email: response.data.user.email })
		return response.data.user
	} catch (error: any) {
		if (error.response?.status === 401) {
			logger.warn('Token validation failed: invalid token', { token: token.substring(0, 8) + '...' })
			throw { status: 401, message: 'Invalid token' }
		}
		logger.error('Token validation failed: auth service unavailable', { 
			error: error.message,
			status: error.response?.status 
		})
		throw { status: 500, message: 'Auth service unavailable' }
	}
}

export const getUserById = async (userId: string): Promise<User> => {
	logger.debug('Fetching user by ID from auth service', { userId })
	try {
		const response = await axios.get(`${AUTH_SERVICE_URL}/api/v1/internal/users/${userId}`)
		logger.debug('User retrieved successfully', { userId, email: response.data.user.email })
		return response.data.user
	} catch (error: any) {
		if (error.response?.status === 404) {
			logger.warn('User not found in auth service', { userId })
			throw { status: 404, message: 'User not found' }
		}
		logger.error('Failed to fetch user: auth service unavailable', { 
			userId,
			error: error.message,
			status: error.response?.status 
		})
		throw { status: 500, message: 'Auth service unavailable' }
	}
}
