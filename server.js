const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const fs = require('fs'); //file operations
const bcrypt = require('bcrypt');




const app = express();
const PORT = 3000;


//middleware
app.use(bodyParser.urlencoded({ extended: true}));

app.use(express.static('Frontend'))
app.use(express.static('assets'))


// Init session middleware
app.use(session({
    secret:'yuvi2003',
    resave: false,
    saveUninitialized: true,
    cookie: { secure:false}
}));


// Home
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/Frontend/index.html');
});



//Sign-Up Route (hash password added during signup)
app.post('/signup', async(req, res) => {
    const { username, email, password, cpassword } = req.body;

    if(password !== cpassword){
        return res.send('Passwords do not match. ');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userData = { username, email, password: hashedPassword };


    // console.log(`User: ${username}, Email: ${email}, Password: ${password}`);
    
    fs.readFile('users.json', (err, data)=>{
        let users = [];

        if(!err && data.length >0){
            users = JSON.parse(data);
        }

        users.push(userData);

        fs.writeFile('users.json', JSON.stringify(users), (err) => {
            if(err){
                console.error('Error saving user:', err);
                return res.status(500).send('Error saving user.');
            }
            res.redirect('/login.html')

        });
    });
    // res.send('User Signed up successfully!!!');
});



//Login
app.post('/login', async (req, res) => {
    const {email, password} = req.body;
    fs.readFile('users.json', async (err, data) => {
        if(err){
            console.error('Error reading user data:', err)
            return res.status(500).send('Internal Server Error');
        }
        let users = [];
        if(data.length >0){
            users = JSON.parse(data);
        }
        const user = users.find(u => u.email === email );

        if(user && await bcrypt.compare(password, user.password)){
            req.session.user = user;
            res.redirect('/dashboard.html');
        }else{
            res.redirect('/login.html?error=Invalid email or password');
        }
    });
});

// Middleware to protect routes
const requireLogin = (req, res, next)=> {
    if(!req.session.user){
        return res.redirect('/login.html')
    }
    next();
};

app.get('/logout', (req, res)=> {
    req.session.destroy(err => {
        if(err){
            return res.status(500).send('Error logging out');
        }
        res.redirect('/login.html')
    });
});

app.get('/getUser', (req, res) => {
    if(req.session.user){
        res.json({ username:req.session.user.username});
    }else{
        res.status(401).send('Unauthorized');
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});