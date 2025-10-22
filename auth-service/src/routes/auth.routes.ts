import { Router } from 'express'
import { authenticate } from '../middleware/auth.middleware'
import * as ctrl from '../controllers/auth.controller'

const router: Router = Router()

router.post('/register', ctrl.register)
router.post('/login', ctrl.login)
router.post('/2fa/login', ctrl.verifyLogin2FA) 

router.post('/refresh', ctrl.refresh)
router.post('/password-reset/request', ctrl.requestPasswordReset)
router.post('/password-reset/confirm', ctrl.confirmPasswordReset)

router.get('/me', authenticate, ctrl.me)

router.post('/logout', ctrl.logout)

router.post('/otp/request', ctrl.requestOTP)

router.post('/otp/verify', ctrl.verifyOTP)

router.post('/2fa/enable', authenticate, ctrl.enable2FA)
router.post('/2fa/verify', authenticate, ctrl.verify2FA)

export default router 