const router = require('express').Router()
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../users/users-model')
const { checkUsernameExists, validateRoleName } = require('./auth-middleware')
const { JWT_SECRET, ROUNDS } = require('../secrets') // use this secret!

router.post('/register', validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  const credentials = req.body
  try {
    credentials.password = bcrypt.hashSync(credentials.password, ROUNDS)
    credentials.role_name = req.role_name
    const newUser = await User.add(credentials)
    res.status(201).json({
      user_id: newUser.user_id,
      username: newUser.username,
      role_name: newUser.role_name
    })
  } catch (err) {
    next(err)
  }
})

router.post('/login', checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  try {
    if (bcrypt.compareSync(req.body.password, req.userExists.password)) {
      const token = buildToken(req.userExists)
      res.json({
        message: `${req.userExists.username} is back!`,
        token: token
      })
    } else {
      res.status(401).json({ message: 'Invalid credentials' })
    }
  } catch (err) {
    next(err)
  }
})

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name
  }
  const config = {
    expiresIn: '1d'
  }
  return jwt.sign(payload, JWT_SECRET, config)
}

module.exports = router
