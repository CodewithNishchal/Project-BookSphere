import express from "express"
import bodyParser from "body-parser"
import PG from "pg"

const app = express()
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static("public"))

app.get("/", (req,res) => {
  res.render("Home.ejs");
})

app.get("/login", (req, res) => {
  res.render("Login.ejs")
})

app.listen(port, () => {
  console.log("App listening at port 3000");
  
})