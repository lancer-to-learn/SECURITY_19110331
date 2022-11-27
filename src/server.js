const express = require('express')
const fs = require('fs')
const https = require('https')
const path = require('path')
const helmet = require('helmet')
const passport = require('passport')
const {Strategy} = require('passport-google-oauth2')
const cookieSession = require('cookie-session')
const PORT = process.env.PORT || 8000

require('dotenv').config()

const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    SECRET_KEY1: process.env.SECRET_KEY1,
    SECRET_KEY2: process.env.SECRET_KEY2,
}

const AUTH_CONFIG = {
    callbackURL: '/auth/google/callback',
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET
}

function verifyCallback(accessToken, refreshToken, profile, done) {
    console.log('Google profile ', profile)
    done(null, profile)
}

passport.use(new Strategy(AUTH_CONFIG, verifyCallback))


passport.serializeUser((user, done) => {
    done(null, user.id)
})

passport.deserializeUser((id, done) => {
    done(null, id)
})
const app = express()

function checkLoggedIn(req, res, next) {
    console.log('Current user is: ', req.user)
    const isLoggedIn = req.isAuthenticated() && req.user
    if (!isLoggedIn) {
        res.status(401).json({
            error: "You must log in!"
        })
        
    }
    next()  
}

app.use(helmet())
app.use(cookieSession({
    name: 'session',
    maxAge: 24*60*60*1000,
    keys: [config.SECRET_KEY1, config.SECRET_KEY2]
}))

app.use(passport.initialize())
app.use(passport.session())

app.get('/auth/google', passport.authenticate('google', {
    scope: ['email'],
}))
app.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
    session: true,
}), (req, res) => {
    console.log('Google is called us back!')
})
app.get('/auth/logout', (req, res) => {
    req.logOut()
    return res.redirect('/')
})

app.use('/secret', checkLoggedIn , (req, res) => {
    res.send('This is secret value!')
})

app.use('/', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'))
})

https.createServer({
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
},app).listen(PORT, ()=> {
    console.log('Listening at port ', PORT)
})