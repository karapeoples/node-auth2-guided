const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

const authRouter = require("../auth/auth-router.js");
const usersRouter = require("../users/users-router.js");
const restricted = require('../auth/restricted-middleware')

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.use("/api/auth", authRouter);
server.use("/api/users", restricted, checkRole('hr'), usersRouter);

server.get("/", (req, res) => {
  res.json({ api: "up" });
});

module.exports = server;

function checkRole(role) {
  return (req,res, next) =>{
    req.decodedToken && req.decodedToken.role  && req.decodedToken.toLowerCase() === role ? next()   
      : res.status(403).json({error: "You do not meet role qualifications"})
  }
}