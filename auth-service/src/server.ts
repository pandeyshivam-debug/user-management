import app from './app'
import logger from './utils/logger'

const PORT = process.env.PORT

app.listen(PORT, () => {
    // console.log(`Auth service running on PORT ${PORT}`)
    logger.info(`Auth servicerunning on PORT ${PORT}`)
})
