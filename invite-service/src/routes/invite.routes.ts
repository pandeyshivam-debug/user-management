import { Router } from 'express'
import * as ctrl from '../controller/invite.controller'
import { authenticate } from '../middleware/auth.middleware'
import { requireRoles } from '../middleware/roles.middleware'

const router: Router = Router()

router.post('/create', authenticate, requireRoles(['SUPER_ADMIN', 'SITE_ADMIN', 'OPERATOR', 'CLIENT_ADMIN']), ctrl.createInvite)
router.post('/verify', ctrl.verifyInvite) 
router.get('/my-invites', authenticate, ctrl.getMyInvites)
router.post('/mark-used', ctrl.markUsed)

export default router
