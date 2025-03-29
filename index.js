require('dotenv').config();
const express = require('express');
const app = express();
const mongoose = require('mongoose');

const {userRouter} = require('./routers/userRouter');
app.use(express.json());

app.use("/api/v1/user", userRouter);

async function main(){
  await mongoose.connect(process.env.MONGO_URL).then(
    console.log("Connected to MONGODB")
  )
  app.listen(3000);
}
main();
