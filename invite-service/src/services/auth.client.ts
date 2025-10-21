import axios from 'axios'

const AUTH_SERVICE_URL = process.env.AUTH_SERVICE_URL || 'http://localhost:3001'

export interface User {
	id: string
	email: string
	role: string
	name: string
}

export const validateToken = async (token: string): Promise<User> => {
	try {
		const response = await axios.post(`${AUTH_SERVICE_URL}/api/v1/internal/validate-token`, {
			token
		})
		return response.data.user
	} catch (error: any) {
		if (error.response?.status === 401) {
			throw { status: 401, message: 'Invalid token' }
		}
		throw { status: 500, message: 'Auth service unavailable' }
	}
}

export const getUserById = async (userId: string): Promise<User> => {
	try {
		const response = await axios.get(`${AUTH_SERVICE_URL}/api/v1/internal/users/${userId}`)
		return response.data.user
	} catch (error: any) {
		if (error.response?.status === 404) {
			throw { status: 404, message: 'User not found' }
		}
		throw { status: 500, message: 'Auth service unavailable' }
	}
}
