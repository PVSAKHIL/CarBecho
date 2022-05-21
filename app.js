const bp=require('body-parser')
const express=require('express');
const ejs=require('ejs');
const mongoose=require('mongoose');
const session=require('express-session')
const passport=require('passport');
const plm=require('passport-local-mongoose');
const md5=require('md5');
const bcrypt=require('bcrypt-nodejs');
var fs = require('fs');
var path = require('path');
var multer= require('multer');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app=express()
var msg="";
var i=0;
app.use(bp.urlencoded({extended:true}))
app.use(express.static('public'));
app.set('view engine','ejs');
app.use(session({
    secret:"secret cookie",
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.DATABASE, {useNewUrlParser: true, useUnifiedTopology: true});

const userschema= new mongoose.Schema({
    name: String,
    email : String,
    phone :String,
    password: String,
    otp: String,
    otpexpire: Date,
    username: Number
});

const staffschema= new mongoose.Schema({
  name: String,
  email: String,
  phone: String,
  addedby: String,
  password: String,
  otp: String,
  otpexpire: Date
});

const carschema=new mongoose.Schema({
  carOwner: String,
  carMediator: String,
  model: String,
  brand: String,
  price: String,
  others: String,
  orderedby: {type: String,default: ""},
  boughtdate: {type: Date,default: Date.now()},
  image: {
    path: String
  }
});

useraddressschema=new mongoose.Schema({
  email: String,
  dno: String,
  landmark: String,
  street: String,
  city: String,
  state: String,
  country: String
});

sellerschema= new mongoose.Schema({
  email: String,
  date: Date,
  carno: String,
  rcno: String
});

dummyuserschema=new mongoose.Schema({
  name: String,
  email: String,
  phone: String,
  addedby: String,
  otp: String,
  otpexpire: Date
});

dummystaffschema=new mongoose.Schema({
  name: String,
  email: String,
  addedby: String,
  phone: String,
  otp: String,
  otpexpire: Date
})

userschema.pre('save', function(next) {
    var user = this;
    var SALT_FACTOR = 5;
  
    if (!user.isModified('password')) return next();
  
    bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
      if (err) return next(err);
  
      bcrypt.hash(user.password, salt, null, function(err, hash) {
        if (err) return next(err);
        user.password = hash;
        next();
      });
    });
  });
  
  userschema.methods.comparePassword = function(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
      if (err) return cb(err);
      cb(null, isMatch);
    });
  };
userschema.plugin(plm);

staffschema.pre('save', function(next) {
  var user = this;
  var SALT_FACTOR = 5;

  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});

staffschema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};
userschema.plugin(plm);
const User=mongoose.model('User',userschema);
const Staff=mongoose.model('Staff',staffschema);
const Car=mongoose.model('Car',carschema);
const Useraddress=mongoose.model('Useraddress',useraddressschema);
const Seller=mongoose.model('Seller',sellerschema);
const Dummyuser=mongoose.model('Dummyuser',dummyuserschema);
const Dummystaff=mongoose.model('Dummystaff',dummystaffschema);
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  if(user!=null){
    done(null,user);
  }
});
var storage = multer.diskStorage({
  destination: (req, file, cb) => {
      cb(null, 'public/uploads')
  },
  filename: (req, file, cb) => {
      cb(null, file.fieldname + '-' + Date.now()+path.extname(file.originalname))
  }
});
var upload = multer({ storage: storage });

let transporter = nodemailer.createTransport({
  host: 'smtp@gmail.com',
  port: 465,
  secure: true,
  service: 'gmail',
  auth:{
      user: process.env.USER_NAME,
      pass: process.env.PASSWORD
  }
});

app.get('/stafflogin',function(req,res){
  res.render('stafflogin',{msg:""});
});
app.get('/staffregister',function(req,res){
  res.render('staffregister',{msg:msg,email: req.user.email});
});
app.get('/login',function(req,res){
    res.render('login',{msg:""});
});
app.get('/register',function(req,res){
    res.render('register',{msg:msg});
});
app.get('/',function(req,res){
    if(req.isAuthenticated()){
        var cars=Car.find({orderedby:""},function(err,foundcars){
          res.render('main',{email: req.user.email,cars:foundcars ,dirname: __dirname});
        })
    }
    else{
        console.log("hello");
    }
});

app.get('/staff',function(req,res){
  if(req.isAuthenticated()){
      res.render('staff',{email: req.user.email,name: req.user.name});
  }
  else{
      console.log("hello");
  }
});
app.get('/orders',function(req,res){
  Car.find({orderedby: req.user.email},function(err,foundorders){
    res.render("orders",{cars: foundorders});
  });
  });
app.get("/sell",function(req,res){
  res.render("sell",{msg:""});
});
app.get("/address",function(req,res){
  Useraddress.findOne({email: req.user.email},function(err,foundaddress){
    res.render("address",{address: foundaddress});
  })
});
app.get("/changeaddress",function(req,res){
  Useraddress.deleteOne({ email: req.user.email }, function (err,bool) {
    res.render("address",{address: null})
  });
});
app.get("/forgot",function(req,res){
  res.render("forgot.ejs",{msg:""});
})
app.get('/logout',function(req,res){
  req.logout();
  res.redirect('/login');
});
app.get('/stafflogout',function(req,res){
  req.logout();
  res.redirect('/stafflogin');
});
app.post('/register',function(req,res){
    if(/[a-zA-Z ]*/.test(req.body.name)===false){
        var msg="invalid name";
        res.render('register',{msg: msg});
    }
    else if(/[0-9]{10}/.test(req.body.phone)===false){
        var msg="invalid phone number";
        res.render('register',{msg: msg});
    }
    else if(req.body.password!=req.body.confirmPassword){
      var msg="passwords didnt match";
      res.render('register',{msg:msg})
    }
    else{
    	const user =new Dummyuser({
                        name: req.body.name,
                        email: req.body.email,
                        phone: req.body.phone,
                        });
        User.findOne({$or: [{email : req.body.email},{phone : req.body.phone}]},function(err,founduser){
        	     if(err){
        	     	console.log(err)
        	     	}
                    else if(founduser==null){  
                      let otp = Math.random();
                      otp = otp * 1000000;
                      otp = parseInt(otp);
                      // console.log(otp);
                      user.otp = otp;
                      user.otpexpire = Date.now() + 3600000;
                      Dummyuser.deleteMany({email : req.body.email}, (err, foundDummy)=>{
                        if(!err)
                        {}
                        else
                        console.log(err);
                        })   
                        user.save();
                        var mailOptions = {
                          to: req.body.email,
                          subject: 'OTP for your registration',
                          html: '<h3>OTP for verification is </h3>' + '<h1>'+ otp +'</h1>'
                      };
  
                      transporter.sendMail(mailOptions, (err, info)=>{
                          if(err){
                              console.log(err)
                          }else{
                              res.render('otp', {msg:'otp sent sucessfully to '+ req.body.email, email: req.body.email})
                          }
                      })

                            }
                    else{
                        var msg="account already exists";
                        res.render('register',{msg: msg});
                    }
                        });
                    }
        });
        app.post('/verifyotp', (req,res)=>{
          Dummyuser.findOne({email: req.body.email, otpexpire: {$gt: Date.now()}}, function(err, foundUser){
              if(err){
                console.log(err)
              }else{
                if(!foundUser){
                  res.render('otp', {email: req.body.email, msg: 'otp expired click resend otp'})
                }else{
                  if(foundUser.otp == req.body.otp){
                    res.render('createpassword', {msg:'Successfully Verified', email: req.body.email})
                  }else{
                    res.render('otp', {email: req.body.email, msg: 'incorrect otp'})
                  }
                }
              }
          });
      });
      app.post('/resendotp', (req,res)=>{
        Dummyuser.findOne({email : req.body.email}, (err, user)=>{
            if(!err)
            {
                if(user)
                {
                    let otp = Math.random();
                    otp = otp * 1000000;
                    otp = parseInt(otp);
                    user.otp = otp;
                    user.otpexpire = Date.now() + 3600000;
                    user.save();
                    var mailOptions = {
                        to: req.body.email,
                        subject: 'OTP for your registration',
                        html: '<h3>OTP for verification is </h3>' + '<h1>'+ otp +'</h1>'
                    };
    
                    transporter.sendMail(mailOptions, (err, info)=>{
                        if(err){
                            console.log(err)
                        }else{
                            res.render('otp', {msg:'otp sent sucessfully to '+ req.body.email, email: req.body.email})
                        }
                    })
                }
            }
        })
    })
      app.post('/createpassword', (req,res)=>{
        Dummyuser.findOne({email : req.body.email}, (err,foundUser)=>{
            if(!err)
            {
                var user = new User({
                    name : foundUser.name,
                    email : foundUser.email,
                    phone : foundUser.phone,
                    password : req.body.password,
                    username : i
                })
                i+=1;
                user.save();
                Dummyuser.deleteOne({email: req.body.email},function(err,bool){
                  res.redirect('login');
                });
            }
        })
    });
    app.post("/verifyingotp",function(req,res){
      User.findOne({email : req.body.email}, (err, user)=>{
        if(!err)
        {
            if(user)
            {
                let otp = Math.random();
                otp = otp * 1000000;
                otp = parseInt(otp);
                user.otp = otp;
                user.otpexpire = Date.now() + 3600000;
                user.save();
                var mailOptions = {
                    to: req.body.email,
                    subject: 'OTP for your registration',
                    html: '<h3>OTP for verification is </h3>' + '<h1>'+ otp +'</h1>'
                };

                transporter.sendMail(mailOptions, (err, info)=>{
                    if(err){
                        console.log(err)
                    }else{
                        res.render('otpfor', {msg:'otp sent sucessfully to '+ req.body.email, email: req.body.email})
                    }
                });
            }
            else{
              res.render("forgot.ejs",{msg:"Invalid Email"});
            }
        }
    });
    });
    app.post("/createnewpassword",function(req,res){
      User.findOne({email: req.body.email, otpexpire: {$gt: Date.now()}}, function(err, foundUser){
        if(err){
          console.log(err);
        }else{
          if(!foundUser){
            res.render('otp', {email: req.body.email, msg: 'otp expired click resend otp'})
          }else{
              console.log(foundUser.otp);
              console.log(req.body.otp);
            if(foundUser.otp == req.body.otp)
            {
              res.render('createnewpassword', {msg:'Successfully Verified', email: req.body.email})
            }
            else
            {
              res.render('otpfor', {email: req.body.email, msg: 'incorrect otp'})
            }
          }
        }
    });
    });
    app.post('/resetpassword', (req, res)=>{
      if(req.body.email == null)
      {
          res.send("Please come after some time...")
      }
      User.findOne({email : req.body.email}, (err, resp)=>{
          if(err)
          {
              console.log(err);
          }
          else
          {
              resp.password = req.body.password;
              resp.save();
              req.logout();
              res.redirect('login');
          }
      });
  })
        app.post('/staffregister',function(req,res){
          if(/[a-zA-Z ]*/.test(req.body.name)===false){
              var msg="invalid name";
              res.render('staffregister',{msg: msg});
          }
          else if(/[0-9]{10}/.test(req.body.phone)===false){
              var msg="invalid phone number";
              res.render('staffregister',{msg: msg});
          }
          else if(req.body.password!=req.body.confirmPassword){
            var msg="passwords didnt match";
            res.render('staffregister',{msg:msg})
          }
          else{
            const staff =new Dummystaff({
                              name: req.body.name,
                              email: req.body.email,
                              addedby: req.user.email,
                              phone: req.body.phone});
              Staff.findOne({$or: [{email : req.body.email},{phone : req.body.phone}]},function(err,founduser){
                     if(err){
                       console.log(err)
                       }
                          else if(founduser==null){    
                            let otp = Math.random();
                            otp = otp * 1000000;
                            otp = parseInt(otp);
                            staff.otp = otp;
                            staff.otpexpire = Date.now() + 3600000;
                            Dummystaff.deleteMany({email : req.body.email}, (err, foundDummy)=>{
                              if(!err)
                              {}
                              else
                              console.log(err);
                              });   
                              staff.save()
                              var mailOptions = {
                                to: req.body.email,
                                subject: 'OTP for your registration',
                                html: '<h3>OTP for verification is </h3>' + '<h1>'+ otp +'</h1>'
                                };
                                transporter.sendMail(mailOptions, (err, info)=>{
                                    if(err){
                                        console.log(err)
                                    }else{
                                        res.render('staffotp', {msg:'otp sent sucessfully to '+ req.body.email, email: req.body.email})
                                    }
                                });
                          }
                          else{
                              var msg="account already exists";
                              res.render('staffregister',{msg: msg});
                          }
                              });
                          }          
              });
              app.post('/staffverifyotp', (req,res)=>{
                Dummystaff.findOne({email: req.body.email, otpexpire: {$gt: Date.now()}}, function(err, foundUser){
                    if(err){
                      console.log(err)
                    }else{
                      if(!foundUser){
                        res.render('staffotp', {email: req.body.email, msg: 'otp expired click resend otp'})
                      }else{
                        if(foundUser.otp == req.body.otp){
                          res.render('staffcreatepassword', {msg:'Successfully Verified', email: req.body.email})
                        }else{
                          res.render('staffotp', {email: req.body.email, msg: 'incorrect otp'})
                        }
                      }
                    }
                });
            });     
            app.post('/staffcreatepassword', (req,res)=>{
              Dummystaff.findOne({email : req.body.email}, (err,foundUser)=>{
                  if(!err)
                  {
                      var user = new Staff({
                          name : foundUser.name,
                          email : foundUser.email,
                          phone : foundUser.phone,
                          addedby: foundUser.addedby,
                          password : req.body.password
                      });
                      user.save();
                      Dummystaff.deleteOne({email: req.body.email},function(err,bool){
                        res.redirect('staff');
                      });
                  }
              })
          });
          app.post('/staffresendotp', (req,res)=>{
            Dummystaff.findOne({email : req.body.email}, (err, user)=>{
                if(!err)
                {
                    if(user)
                    {
                        let otp = Math.random();
                        otp = otp * 1000000;
                        otp = parseInt(otp);
                        user.otp = otp;
                        user.otpexpire = Date.now() + 3600000;
                        user.save();
                        var mailOptions = {
                            to: req.body.email,
                            subject: 'OTP for your registration',
                            html: '<h3>OTP for verification is </h3>' + '<h1>'+ otp +'</h1>'
                        };
        
                        transporter.sendMail(mailOptions, (err, info)=>{
                            if(err){
                                console.log(err)
                            }else{
                                res.render('staffotp', {msg:'otp sent sucessfully to '+ req.body.email, email: req.body.email})
                            }
                        })
                    }
                }
            })
        });
var LocalStrategy=require('passport-local').Strategy
passport.use('user-local',new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
  },function(email, password, done) {
    User.findOne({ email: email }, function(err, user) {
      if (err) return done(err);
      if (!user) return done(null, false, { message: 'Incorrect username.' });
      user.comparePassword(password, function(err, isMatch) {
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      });
    });
  }))
  var LocalStrategy=require('passport-local').Strategy;
passport.use('staff-local',new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
  },function(email, password, done) {
    Staff.findOne({ email: email }, function(err, user) {
      if (err) return done(err);
      if (!user) return done(null, false, { message: 'Incorrect username.' });
      user.comparePassword(password, function(err, isMatch) {
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      });
    });
  }));

  app.post("/login", function(req, res, next){
    passport.authenticate("user-local", function(err, user, info){
        if(err){ return next(err);}
        if(!user){return res.render("login", {msg : info.message})}
        req.logIn(user, function(err){
            if(err){ return next(err); }
            return res.redirect("/");
        });
    })(req, res, next)
});
app.post("/stafflogin", function(req, res, next){
  passport.authenticate("staff-local", function(err, user, info){
      if(err){ return next(err);}
      if(!user){return res.render("stafflogin", {msg : info.message})}
      req.logIn(user, function(err){
          if(err){ return next(err); }
          return res.redirect("/staff");
      });
  })(req, res, next)
});
app.post("/staff",upload.single('photo'),function(req,res){
  var img=fs.readFileSync(path.join(__dirname+ '/'+ req.file.path));
  var encoded_image=img.toString('base64')
  var car= new Car({
    carOwner: req.body.email,
    carMediator: req.user.email,
    model: req.body.model,
    brand: req.body.brand,
    price: req.body.price,
    others: req.body.others,
    image: {
      path: req.file.path.slice(7,)
  }});
  car.save();
  res.redirect('staff');
});
app.post("/item",function(req,res){
  Car.findOne({_id: req.body.id},function(err,foundCar){
    res.render("item",{msg:"",car: foundCar});
  });
});
app.post("/addtoorders",function(req,res){
  Car.findOne({_id: req.body.id},function(err,foundcar){
    if(foundcar){    
  Useraddress.findOne({email: req.user.email},function(err,foundaddress){
    if(foundaddress){
      foundcar.orderedby=req.user.email;
      foundcar.boughtdate=Date.now();
      foundcar.save();
      res.redirect("/orders");
    }
    else{
      res.render("item",{msg:"Add your Address first",car: foundcar })
    }
  });
    }
  });
});
app.post("/cancelorder",function(req,res){
  Car.findOne({_id: req.body.id},function(err,foundcar){
    if(foundcar){
    foundcar.orderedby="";
    foundcar.save();
    res.redirect('/orders');
    }
  })
});

app.post("/search",function(req,res){
  Car.find({$and:[{brand: req.body.car},{orderedby:""}]},function(err,foundcars){
    res.render("main",{email:req.user.email,cars:foundcars});
  });
});
app.post("/addaddress",function(req,res){
  var address=new Useraddress({
    email: req.user.email,
    dno: req.body.dno,
    landmark: req.body.landmark,
    street: req.body.street,
    city: req.body.city,
    state: req.body.state,
    country: req.body.country
  });
  address.save(function(err,result){
    res.render("address",{address: address});
  });
});
app.post("/sell",function(req,res){
  console.log(req)
  Seller.findOne({email: req.user.email},function(err,foundseller){
    if(!foundseller){
      Useraddress.findOne({email: req.user.email},function(err,foundaddress){
        if(!foundaddress){
          res.render("sell",{msg:"Add your Address first"})
        }
        else{
          var seller= new Seller({
            email: req.user.email,
            rcno: req.body.rcno,
            carno: req.body.carno,
            date: Date.now()
          });
          seller.save();
          res.render("sell",{msg: "Successfully added as Seller "});
        }
      });
    }
    else{
      res.render("sell",{msg:"You are already a Seller"});
    }
  });
});
app.post("/item1",function(req,res){
  Car.findOne({_id: req.body.id},function(err,foundcar){
    res.render("item1",{car: foundcar});
  })
});
app.listen(process.env.PORT,function(req,res){
    console.log("server started");
});