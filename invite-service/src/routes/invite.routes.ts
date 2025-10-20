import { Router } from 'express'
import * as ctrl from '../controller/invite.controller'
import { authenticate } from '../middleware/auth.middleware'
import { requireRoles } from '../middleware/roles.middleware'

const router: Router = Router()

router.post('/create', authenticate, requireRoles(['SUPER_ADMIN', 'SITE_ADMIN', 'OPERATOR']), ctrl.createInvite)
router.post('/verify', ctrl.verifyInvite) // Public endpoint for registration process
router.get('/my-invites', authenticate, ctrl.getMyInvites)

export default router
