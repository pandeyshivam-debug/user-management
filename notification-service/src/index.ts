import dotenv from 'dotenv'
import { connectDatabase, disconnectDatabase } from './config/database.config'
import { connectRabbitMQ, closeRabbitMQ } from './config/rabbitmq'
import { startRegistrationConsumer } from './consumers/registration.consumers'

dotenv.config()

const startService = async () => {
    try {
        console.log('Starting Notification Service...')

        // Connect to MongoDB
        await connectDatabase()

        // Connect to RabbitMQ
        const channel = await connectRabbitMQ()

        // Start consuming messages
        await startRegistrationConsumer(channel)

        console.log('Notification Service is running')
    } catch (error) {
        console.error('Failed to start service:', error)
        // process.exit(1)
    }
}

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\nShutting down gracefully...')
    await closeRabbitMQ()
    await disconnectDatabase()
    process.exit(0)
})

process.on('SIGTERM', async () => {
    console.log('\nShutting down gracefully...')
    await closeRabbitMQ()
    await disconnectDatabase()
    process.exit(0)
})

startService()
