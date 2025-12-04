import app from './app'
import logger from './utils/logger'

const PORT = process.env.PORT

app.listen(PORT, () => {
    logger.info('Auth service started', { port: PORT, env: process.env.NODE_ENV })
})
