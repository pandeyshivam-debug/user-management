import { Router } from 'express'
import * as ctrl from '../controllers/auth.controller'
import { authenticate } from '../middleware/auth.middleware'
import { requireRoles } from '../middleware/roles.middleware'

const router: Router = Router()

router.post('/register', ctrl.register)
router.post('/login', ctrl.login)
router.post('/refresh', ctrl.refresh)
router.post('/password-reset/request', ctrl.requestPasswordReset)
router.post('/password-reset/confirm', ctrl.confirmPasswordReset)

router.get('/me', authenticate, ctrl.me)

router.post('/invite', authenticate, requireRoles(['SUPER_ADMIN', 'SITE_ADMIN', 'OPERATOR']), ctrl.invite)

router.post('/logout', ctrl.logout)

export default router 