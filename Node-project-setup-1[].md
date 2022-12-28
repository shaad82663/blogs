# **NodeJs Project Setup**

---

---

**Author : Mohd Shadab**

**Email : shaad82663@gmail.com**

**Pre-requisites : NodeJS Enviroment, Npm, Git Bash, Code Editor (VSCode prefered).**

Meta data : Blog version:  v1.0.0 \[Updates are active\] ,  Last update : 29-Dec-2022

### 1.A) Basic Setup

1. in git,

```bat
mkdir p
cd p
mkdir front back
npm i <dependencies>
cd back
```

2. inside back/

touch app.js server.js

3. in app.js 

   ```js
   const express = require("express");
   const app = express();
   
   module.exports = app;
   ```

4. in sever.js

   ```js
   const app = require(“./app”);
   
   app.listen(process.env.PORT, () => {
     console.log(`Listening port ${process.env.PORT} in ${process.env.NODE_ENV} mode`);
   }
   ```

5. in /back

   mkdir config -> cd config -> touch config.env

6. in config.env

   ```js
   PORT=4000
   NODE_ENV= DEVELOPMENT
   ```

  7\. In server.js, use config file

```js
     const dotenv = require(“dotenv”);
     dotenv.config({  path: “back/config/config.env” });
```

### 1.B) Creating Route

1.  ./back -> mkdir controllers routes

2. ./back/controllers  touch productController.js

   ```js
   exports.test= (req, res, next) => {
   
       res.status(201).json({
           success : true, 
           message : "This is just for testing purpose"
       })
   }
   ```

   1.  ./routes  touch product.js

      3. 

         ```
         const express = require('express');
         const router = express.Router();
         const {test} = require('../controllers/userController');
         router.route('/test-route').post(test);
         
         module.exports = router;
         ```

      4.  Import and use the user route in app.js

         ```js
         app.use(express.json());
         //Import all routesconst 
         const product= require('./routes/product');
         app.use('/api/v1', product);
         //root url : localhost:4000/api/v1/... for al routes of student 
         //e.g. localhost:4000/api/v1/new-user
         ```

        -> app.js \[updated\]

      ```js
      const express = require('express');
      const app = express();
      
      app.use(express.json());
      //Import all routesconst 
      const product= require('./routes/product');
      
      app.use('/api/v1', product);
      module.exports = app;
      ```

      ```js
       npm run dev 
      ```

### 1.C) Connecting to DB

./config touch database.js

1. In database.js

   ```js
   const mongoose = require('mongoose');
   const connectDB = () => {
       mongoose.connect("mongodb://localhost:27017/payment", { 
           useNewUrlParser: true,
           useUnifiedTopology: true
       }).then(con => {
           console.log(`Connected to DB with host:${con.connection.host}`)
       })
   }
   module.exports = connectDB;
   ```

2. in app.js

   ```js
   ...
   const connectDB = require('./config/database');
   ...
   //Connect to DB
   connectDB();
   //app.listen
   ```

   app.js\[Updated\]

   ```js
   const express = require('express');
   const app = express();
   
   const connectDB = require('./config/database');
   
   app.use(express.json());
   
   //Import all routes
   const user = require('./routes/user');
   
   //Connect to DB
   connectDB();
   
   app.use('/api/v1', user);
   module.exports = app;
   ```

3.  Creating Model for the user

   ./back-end mkdir models -> cd models -> product.js

4. In ./back/models/product.js

   ```js
   const mongoose = require("mongoose");
   
   const productSchema = new mongoose.Schema({
      name : {
          type : String,
          required : [true, "Please Enter your product name"],
          trim : true,
          maxLength : [100, "Product length cannot exceed 100 characters"]
      }, 
      price : {   
       type : Number,
       required : [true, 'Please enter product price'],
       maxLength : [7, "Product length cannot exceed 100 Numbers"],
       default : 0.0
      },
      description : {
       type : String,
       required : [true, 'Please enter product description']
      },
      ratings : {
          type : Number,
          default : 0
      },
      images : [{
          public_id : {
              type : String, 
              required : true
          },
          url : {
              type : String,
              required : true
          }
      }],
      category : {
          type : String,
          required : [true, "Please select category for this product"],
          enum :  [
                  'Electronics',
                  'Cameras',
                  'Laptops',
                  'Headphones',
                  'Food',
                  'Clothes',
                  'Beauty/Health', 
                  'Sports',
                  'Headphones',
                  'Accessories'
              ],
      },
      seller : {
          type : String, 
          required : [true, "Please enter product seller"]
      },
      stock : {
          type : Number,
          required : [true, "Pleaese enter product stock"],
          maxLength : [5, "Product sock can not be more than 99999"],
          default : 0
      },
      numOfReviews : {
       type : Number,
       default : 0
      },
      reviews : [
       {
           user : {
               type : mongoose.Schema.ObjectId,
               ref : 'User',
               requierd : true
              },
           name : {
               type : String,
               required : true
           },
           rating : {
               type : Number,
               required : true
           },
           comment : {
               type : String,
               required : true
           }
       }
      ],
       createdAt : {
         type : Date,
         default : Date.now
      }
   })
   
   module.exports = mongoose.model("Product", productSchema);
   ```

5. Now we will create a product to perform operation in db.

   in productController.js,

   ```js
   ...
   const Product = require("../models/products");//model of product.
   //Create new Product.  {domain}/api/v1/admin/product/new
   exports.newProduct = async (req, res, next) => {
   
       req.body.user = req.user.id;
   
       const product = await Product.create(req.body);
   
       res.status(201).json({
           success : true,
           product
       })
   }
   ...
   ```

   using this route in app.js,

   in ./routes/product.js

   ```js
   const express = require("express");
   const router = express.Router();
   
   const {newProduct} = require("../controllers//productController");
   router.route("/admin/product/new").post(newProduct);
   ...
   
   module.exports = router;
   ```

   Now we can create product which are stored in db.

### 1.D) Error Handling 

1. In ./back mkdir utils -> cd utils ->     touch ErrorHandler.js 

```js
//Error Handler Class
class ErrorHandler extends Error {
     constructor(message, statusCode){
         super(message);
         this.statusCode = statusCode;

         Error.captureStackTrace(this, this.constructor);
     }  
}
module.exports = ErrorHandler;
```

2. We need to create middleware to use this errorHnadler class

   Creating middleware,

   ./back mkdir middlewares -> cd -> touch errors.js

   ```js
   const ErrorHandler = require("../util/errorHandler");
   
   module.exports = (err, req, res, next) => {
       err.statusCode = err.StatusCode || 500;
       err.message = err.message || "Inernal Server Error";
   
        res.status(err, statusCode).json({
          success : false,
          error : err
        })
   }
   ```

   Now we need to use this middleware inside app.js

   ```js
   ...
   const errorMiddleware = require("./middlewares/errors");
   ...
   //Middleware to handle the error. [user after using routes.]
   app.use(errorMiddleware);
   ...
   ```

3. **How can we use it for handling error?**

   In productController.js,

   ```js
   ...
   const ErrorHandler = require("../utils/errorHandler");
   ...
   //inside getProduct controller,
   {
   ...
     if(!product){
       return next(new ErrorHandler("Product not found!", 404));
      }
   ...
   }
   ```

4. Production vs Development Errors

   \[NODE\_ENV=PRODCTION || DEVELOPMENT\]

   in ErrorHandler.js

   ```js
   const ErrorHandler = require("../util/errorHandler");
   
   module.exports = (err, req, res, next) => {
       err.statusCode = err.StatusCode || 500;
   
       if(process.env.NODE_ENV === "DEVELOPMENT"){
           res.status(err.statusCode).json({ 
               success : false,
               error : err, 
               errMessage : err.message,
               stack : err.stack
           }) 
       } 
   
       if(process.env.NODE_ENV === "PRODUCTION"){ 
           let error = {...err};
           error.message = err.messaage;
   
           // Wrong Mongoose Object ID error
           if(err.name === "CastError"){
               const message = `Resourse not found Invalid: ${err.path}`
               error = new ErrorHandler(message, 400);
           }
   
           //Hnaldling mongoose validation error 
           if(err.name === "ValidationError"){
               const message = Object.values(err.errors).map(value => value.message);
               error = new ErrorHandler(message, 400);
           }
   
           //Handling mongoose duplicate key error.
           if(err.code == 11000) {
               const message = `Duplicate ${Object.keys(err.keyValue)} entered.` 
               error = new ErrorHandler(message, 400);
           }
   
           //Handling wrong JWT error
           if(err.name === 'JsonwebTokenError') {
               const message = "JSON web Token is invalid. Try again!!";
               error = new ErrorHandler(message, 400);
           }
   
           if(err.name === 'TokenExpiredError') {
               const message = "Token has expired. Try again!!";
               error = new ErrorHandler(message, 400);
           }
   
   
           res.status(err.statusCode).json({
               success : false,
               message : error.message || "Internal server error"
           })
       }
   
   }
   ```

5. Catching async error.

   inside middlewares, touch catchAsyncError.js

   ```js
   module.exports = func => (req, res, next) => 
                Promise.resolve(func(req,res,next))
                       .catch(next)
   ```

   inside productController.js, wrap the newProduct controller inside catchAsyncError Hnadler,

   ```js
   ...
   const catchAsyncErrors = require("../middlewares/catchAsyncErrors");
   ...
   exports.newProduct = catchAsyncErrors ( async (req, res, next) => {
       req.body.user = req.user.id;
       const product = await Product.create(req.body);
   
       res.status(201).json({
           success : true,
           product
       })
   } )
   ...
   ```

       We can wrap all other routes too.

### 2.A) Authentication and Authorization

(npm : bcrypt, jsonwebtoken, validator, nodemailer, cookie-parser, body-parser)

---

1. **Create User Model**

   inside ./back/models touch user.js

   ```js
   ∨const validator = require("validator");
   const mongoose = require("mongoose");
   const bcrypt = require("bcryptjs");
   const jwt = require("jsonwebtoken");
   const crypto  =  require("crypto"); // pre-installed package. do not need to install.
   
   const userSchema = new mongoose.Schema({
       name : {
           type : String,
           required : [true, "Please enter your name"],
           maxLnegth : [30, "Your name length can not exceed 30 characters."]
       },
       email : {
           type : String,
           required : [true, "Please enter your email"],
           unique : true,
           validate : [validator.isEmail, "Please enter valid email address."]
       },
       password : {
           type : String,
           required : [true, "Please enter password"],
           minLength : [6, "Password must be longer than 6 characters."],
           select : false  // Whenever user is displayed do not display password.
       },
       avtar : {
           public_id : {
             type : String,
             required : true
           },
           url : {
           type : String,
           required : true
           }
       },
       role : {
           type : String,
           default : "user"
       },
       createAt : {
           type : Date,
           default : Date.now
       },
       resetPasswordToken : String,     
       resetPasswordExpire : Date 
   })
   
   module.exports = mongoose.model("User", userSchema);
   ```

2. **Encrypt password while Registration (JWT token)**

   Step 1: .back/controllers touch authController.js

                inside the authController, the registerUser route logic:

   ```js
   ∧...
   const User = require("../models/user");
   
   const ErrorHandler = require("../util/errorHandler");
   const catchAsyncErrors = require("../middlewares/catchAsyncErrors");
   ...
   //Register user. => /api/v1/register
   exports.registerUser =  catchAsyncErrors (async (req, res, next) => {
       const {name, email, password} = req.body;
   
       const user = await User.create({
           name, 
           email,
           password,
           avtar : {
               public_id : "http:xyz.com/abc",
               url : "http:xyz.com/def"
           }
       })
   
       res.status(201).json({
         success : true,
         user
       })
   
   })
   ```

      Step 2: .back/routes, touch auth.js (create route for registration)

```js
∧   const express = require("express");
   const router = express.Router();
  
   const { registerUser} = require("../controllers/authController");
  
   router.route("/register").post(registerUser);
```

      Step 3: In app.js add user route. (import auth.js route in app.js)

```js
∧ ... 
 const auth = require("./routes/auth");
...
app.use("/api/v1", auth);
 ...
```

    Step 4:  Encrypt the password, in .back/models/user.js 

```js
∧...
const bcrypt = require("bcryptjs"); 
//Encrypting password before saving user.
//Note: we can not use this keyword in arrow function.
 userSchema.pre('save', async function (next) {
    //if password is not modifeid then we do not need to encrypt it again.
    if(!this.isModified('password')) {
           next();
    }
    this.password = await bcrypt.hash(this.password, 10);
})
...
```

  Step 5: Generate JSON web token, in .back/models/user.js 

```js
∧...
const jwt = require("jsonwebtoken");
...
//Return JWT token
userSchema.methods.getJwtToken = function() {  //paylod = _id + secret key.
    return jwt.sign({id : this._id}, process.env.JWT_SECRET, {// _id as a payload.
        expiresIn : process.env.JWT_EXPIRES_TIME//e.g. 7d
    }) 
}
...
```

Step 6: inside authController, return token instead user

```js
∧...
const token = user.getJwtToken();
...
res.status(201).json({
    success : true,
    token
})
...
```

3. **Login User & Assign Token**

   Step 1: authController.js logic for login

```js
∧...
//Login user   => /api/v1/login
exports.logInUser = catchAsyncErrors( async (req, res, next) => {
    const {email, password} = req.body;
 
    if(!email || !password) {
        return next(new ErrorHandler("Please enter email and password", 400));
    }  

    const user = await User.findOne({email}).select('+password');

    if(!user) {
       return next(new ErrorHandler("Invalid email or password",401));
    }

    const isPasswordMatched = await user.comparePassword(password);// see the implementation below
    if(!isPasswordMatched){
        return next(new ErrorHandler("Invalid email or password"), 401);
    }
    const token = user.getJwtToken();
    res.status(201).json({
    success : true,
    token
    })   
})
```

 Step 2: Inside models/user

```js
∧...
//Compare user password
userSchema.methods.comparePassword = async function (enteredPassword) {
    return await bcrypt.compare(enteredPassword, this.password);
}
const token = user.getJwtToken();
res.status(201).json({
    success : true,
    token
})
...
```

Step 3: Import route in auth.js route.

```js
∧  ... 
  const { registerUser, login} = require("../controllers/authController");
  
   router.route("/login").post(login);
  ...
```

Step 4: Use auth route in app,js \[Already Used\]

4**. Sending JWT token in Cookie**

```js
∧//Create and send and save token in the cookie.
const sendToken = (user, ststusCode, res) => {
     //Create jwt token 
     const token = user.getJwtToken();

     const options = { 
         expires : new Date(
             Date.now() + process.env.COOKIE_EXPIRES_TIME*24*60*60*1000//7d
         ),
         httpOnly : true//To save the token from being accessed by js code
     }

     //Store the token in cookie.  {'token' : token} <=== {key : value}
     res.status(ststusCode).cookie('token', token, options).json({
         success : true,
         token, 
         user
     })
}

module.exports = sendToken;
```

  Now token is saved in Cookie & also we can use this module in our authentication.

e.g. for registration, Instead

```js
∧...
const token = user.getJwtToken();
res.status(201).json({
    success : true,
    token
})
...
```

just write,

```js
∧...
const sendToken = require("../util/jwttoken");
...
sendToken(user ,200 ,res); 
...
```

5. **Protect routes from unauthentic users**

   Step 1: In ./middlewares touch auth.js

   Step 2: Write auth.js

```js
∧const User = require("../models/user");
const jwt = require("jsonwebtoken");
const ErrorHandler = require("../util/errorHandler");
const catchAsyncErrors = require("./catchAsyncErrors");

//Check if user is authorised or not.
exports.isAuthenticatedUser = catchAsyncErrors( async (req, res, next) => {
    const { token } = req.cookies; 
    
    if(!token) {
        return next(new ErrorHandler("Login first to access resourses.", 401));
    }
 
     //Verifying token using jsonwebtoken (jwt)
     const decoded = jwt.verify(token, process.env.JWT_SECRET);

     //Assigning id to the user.
     req.user = await User.findById(decoded.id);//As we used _id as payload in the jwt token
     next();
}) 
```

  Now we can use isAuthenticatedUser() for verifying that the user is logged in or not.

  Step 3: Inside routes, product.js,

```js
∧...
const { isAuthenticatedUser, authorizeRoles }= require("../middlewares/auth");
...
router.route("/admin/product/new").post(isAuthenticatedUser, newProduct);
...
```

According the above snapped, User will have to login first to add new product in db (admin).

**6**.**Log out the user**

in controllers/authController.js, 

```js
∧//Logout user => /api/v1/logout
exports.logout = catchAsyncErrors( async (req, res, next) => {
    res.cookie('token', null, {
        expires : new Date(Date.now()),
        httpOnly : true
    })

    res.status(200).json({
        success : true,
        message : "Logged out"
    })
})
```

6. **Authorize User Roles and Permissions**

```js
∧//Handling users roles.
exports.authorizeRoles = (...roles) => {//There can be multiple roles, e.g., user, editor, admin so we spreaded it.
    return (req, res, next) => {
        if(!roles.includes(req.user.role)){//e.g., we passed 'admin' role in route but user's role is NOT admin, then we 
        ///Consider it as unauthorized access of the resourse.
            return next(new ErrorHandler(`Role (${req.user.role}) is not allowed to access this resource.`, 403));
        }
        next();//Middleware functionality
    }
}
```

For example, in product.js route, only admin can create the new product.

```js
∧...
const { isAuthenticatedUser, authorizeRoles }= require("../middlewares/auth");
...
router.route("/admin/product/new").post(isAuthenticatedUser,authorizeRoles , newProduct);
//authorizeRoles = for checking the authencity
//isAuthenticatedUser = for checking the accessibility.
```

Note: Most of the functionalities are coded.

Some more functionalities can also be implemented according to the procedures mentioned in the blog.