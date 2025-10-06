import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET

if (!JWT_SECRET) {
    throw new Error("JWT_SECRET not set in environment variables")
}

export const generateAccessToken = (userId: String) => {
    return jwt.sign({userId}, JWT_SECRET, { expiresIn: "15m" })
}

export const generateRefreshToken = (userId: String) => {
    return jwt.sign({userId}, JWT_SECRET, { expiresIn: "7d" })
}

export const verifyToken = (token: string): any => {
    try {
        return jwt.verify(token, JWT_SECRET)
    } catch {
        return null
    }
}