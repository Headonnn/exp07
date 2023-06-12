const argon2 = require("argon2")
require("dotenv").config();

const verifyId=(req,res,next)=>{
    
    
        const id = parseInt(req.params.id);
        const payloadUserId = req.payload ? req.payload.sub : null
        console.log(payloadUserId)
        console.log(req.params.id)
        if(!payloadUserId || id!==req.payload.sub){
            res.status(403).send("Forbidden")
        }
        else{
        next()};
       


}
const hashingOptions =  {
    type: argon2.argon2d,
    memoryCost: 2 ** 16,
    timeCost: 5,
    parrallelism : 1,
};
const jwt = require("jsonwebtoken");
const verifyToken = (req, res, next) => {
    try {
      const authorizationHeader = req.get("Authorization");
  
      if (authorizationHeader === null) {
        throw new Error("Authorization header is missing");
      }
  
      const [type, token] = authorizationHeader.split(" ");
  
      if (type !== "Bearer") {
        throw new Error("Authorization header has not the 'Bearer' type");
      }
  
      req.payload = jwt.verify(token, process.env.JWT_SECRET);
  
      next();
    } catch (err) {
      console.error(err);
      res.sendStatus(401);
    }
  };



const verifyPassword = (req, res,next) => {
    argon2
      .verify(req.user.hashedPassword, req.body.password)
      .then((isVerified) => {
        if (isVerified) {
      
          const payload = { sub: req.user.id };

            const token = jwt.sign(payload, process.env.JWT_SECRET, {
          expiresIn: "1h",
        });

        delete req.user.hashedPassword;
        res.send({ token, user: req.user });
        } else {
          res.sendStatus(401);
        }
        next();
      })
      .catch((err) => {
        console.error(err);
        res.sendStatus(500);
      });
  };
const hashPassword = (req, res, next) => {
    argon2
  .hash(req.body.password, hashingOptions)
  .then((hashedPassword) => {
    console.log(hashedPassword)
    req.body.hashedPassword=hashedPassword
    delete req.body.password
    next();
  })
  .catch((err) => {
    console.log(err)
    res.sendStatus(500)
  });
  };

module.exports = {hashPassword,verifyPassword,verifyToken,verifyId}