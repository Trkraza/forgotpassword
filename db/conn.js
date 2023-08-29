const mongoose = require("mongoose");

const DB = "mongodb://127.0.0.1:27017/app"

mongoose.connect(DB,{
    useUnifiedTopology: true,
    useNewUrlParser: true
}).then(()=> console.log("DataBase Connected")).catch((errr)=>{
    console.log(errr);
})