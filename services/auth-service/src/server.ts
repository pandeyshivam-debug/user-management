import express from 'express'
import 'dotenv/config'

const app = express()

app.use(express.json())

const PORT = process.env.PORT 

app.listen(PORT, () => {
    console.log(`Auth service running on PORT ${PORT}`)
})