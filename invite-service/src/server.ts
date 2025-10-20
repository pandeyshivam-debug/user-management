import app from './app'

const PORT = process.env.PORT || 3002 

app.listen(PORT, () => {
	console.log(`Invite service running on PORT ${PORT}`)
})
