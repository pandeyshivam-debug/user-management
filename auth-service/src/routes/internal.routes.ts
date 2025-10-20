import { Router } from 'express'
import * as ctrl from '../controllers/internal.controller'

const router: Router = Router()

router.post('/validate-token', ctrl.validateToken)
router.get('/users/:userId', ctrl.getUserById)

export default router
