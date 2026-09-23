const express = require('express')
const cors = require('cors')
const mysql = require('mysql2')

const app = express()
require("dotenv").config();

const db = mysql.createConnection({
   host: process.env.DB_HOST,
   port: process.env.DB_PORT,
   user: process.env.BD_USER,
   password: process.env.DB_PASSWORD,
   database: process.env.DB_NAME
})

db.connect((err) => {
   if (err) throw err
})

app.get('/', (req, res) => {
   res.json({ mensagem: 'Ola meu servidor esta rodando' })
})


app.use(cors())
app.use(express.json())



app.listen(3001)