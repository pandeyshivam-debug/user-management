import app from './app'

const PORT = process.env.PORT

app.listen(PORT, () => {
    console.log(`Auth service running on PORT ${PORT}`)
})
