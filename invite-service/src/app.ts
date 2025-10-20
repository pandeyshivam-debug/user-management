import express, { type Express } from 'express'
import 'dotenv/config'
import inviteRoutes from './routes/invite.routes'
import { errorHandler } from './middleware/error.middleware'

const app: Express = express()

app.use(express.json())

app.use('/api/v1/invite', inviteRoutes)

app.use(errorHandler)

export default app
