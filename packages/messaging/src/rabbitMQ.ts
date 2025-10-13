import amqplib from 'amqplib'

let channel: amqplib.Channel

export const connectRabbitMQ = async () => {
    if (channel) return channel
    const conn = await amqplib.connect('amqb://localhost')
    channel = await conn.createChannel()
    await channel.assertExchange('events', 'topic', {durable: true})
    return channel
}

export const publishEvent = async (event: string, payload: any) => {
    const ch = await connectRabbitMQ()
    ch.publish('events', event, Buffer.from(JSON.stringify(payload)))
    console.log(`Published event: {event}`)
}