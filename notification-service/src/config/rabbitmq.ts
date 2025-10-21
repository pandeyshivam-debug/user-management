import amqp, { ChannelModel, Channel } from 'amqplib'

let connection: ChannelModel | null = null
let channel: Channel | null = null

export const connectRabbitMQ = async (): Promise<Channel> => {
    try {
        const rabbitmqUrl = process.env.RABBITMQ_URL || 'amqp://localhost:5672'

        connection = await amqp.connect(rabbitmqUrl)
        channel = await connection.createChannel()

        const queueName = process.env.QUEUE_NAME || 'user_registration_notifications'
        await channel.assertQueue(queueName, { durable: true })

        console.log('RabbitMQ connected successfully')
        console.log(`Queue "${queueName}" is ready`)

        return channel
    } catch (error) {
        console.error('RabbitMQ connection error:', error)
        throw error
    }
}

export const getChannel = (): Channel => {
    if (!channel) {
        throw new Error('RabbitMQ channel not initialized')
    }
    return channel
}

export const closeRabbitMQ = async () => {
    try {
        if (channel) await channel.close()
        if (connection) await connection.close()
        console.log('RabbitMQ connection closed')
    } catch (error) {
        console.error('Error closing RabbitMQ:', error)
    }
}
