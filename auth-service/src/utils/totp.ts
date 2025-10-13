import speakeasy from 'speakeasy'

export const generateTOTPSecret = (email: string) => {
    return speakeasy.generateSecret({
        name: `AuthService (${email})`,
        length: 20
    })
}

export const verifyTOTP = (secret: string, token: string) => {
    return speakeasy.totp.verify({
        secret,
        encoding: 'base32',
        token,
        window: 1
    })
}