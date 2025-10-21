import { Channel } from 'amqplib'
import { createNotification, processNotification } from '../services/notification.service'

export const startRegistrationConsumer = async (channel: Channel) => {
    const queueName = process.env.QUEUE_NAME || 'user_registration_notifications'

    console.log(`🎧 Listening for messages on queue: ${queueName}`)

    channel.consume(
    queueName,
    async (msg) => {
        if (msg) {
            try {
                const content = msg.content.toString()
                const data = JSON.parse(content)

                console.log('📨 Received message:', data)

                // Create notification record
                const notification = await createNotification({
                    type: 'USER_REGISTERED',
                    recipientEmail: data.inviterEmail,
                    recipientName: data.inviterName,
                    inviteeEmail: data.newUserEmail,
                    inviteeName: data.newUserName,
                    inviteeRole: data.newUserRole,
                })

                await processNotification(notification.id)

                // Acknowledge message
                channel.ack(msg)
                console.log('Message processed and acknowledged')
            } catch (error) {
                console.error('Error processing message:', error)
                channel.nack(msg, false, true)
            }
        }
    },
    { noAck: false }
    )
}
