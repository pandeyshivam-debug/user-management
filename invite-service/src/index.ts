import express from 'express'
import dotenv from 'dotenv'
// import inviteRoutes from './routes/invite.routes'

dotenv.config()

const app = express()
app.use(express.json())

// app.use('/api/v1/invites', inviteRoutes)

const PORT = process.env.PORT || 3001
app.listen(PORT, () => console.log(`Invite-service running on port ${PORT}`))
