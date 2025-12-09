import app from './app'
import logger from './utils/logger'

const PORT = process.env.PORT || 3002 

app.listen(PORT, () => {
	logger.info('Invite service started', { port: PORT, env: process.env.NODE_ENV })
})
