const express = require('express');
const mysql = require('mysql2');
const fileuploader = require('express-fileupload');
const path = require('path');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const app = express();
const nodemailer = require("nodemailer");

// Database connection setup
require('dotenv').config();

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    port: 3306,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    dateStrings: true,
    connectionLimit: 20,        // Support 20 concurrent connections
    acquireTimeout: 60000,
    timeout: 60000,
    queueLimit: 0,             // No limit on queued connections
    charset: 'utf8mb4'
};

// Use connection pool for multiple users
const dbCon = mysql.createPool(dbConfig);

// Test database connection
dbCon.getConnection(function (err, connection) {
    if (err) {
        console.error("Error connecting to database:", err);
        process.exit(1);
    } else {
        console.log("Connected to database");
        connection.release();
    }
});

// Database connection monitoring
dbCon.on('connection', function (connection) {
    console.log('New connection established as id ' + connection.threadId);
});

dbCon.on('error', function (err) {
    console.error('Database error: ', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST') {
        console.log('Pool will handle reconnection automatically');
    }
});

// Rate limiting for authentication endpoints
// More reasonable rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // 50 login attempts per 15 minutes
    message: 'Too many authentication attempts, please try again later.'
});

const generalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 500, // 500 requests per minute (much more reasonable)
    message: 'Too many requests, please slow down.'
});

// Apply general rate limiting
app.use(generalLimiter);

// Middleware setup with size limits for multiple users
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.json({ limit: '10mb' }));
app.use(fileuploader({
    limits: {
        fileSize: 10 * 1024 * 1024,  // 10MB per file
        files: 5                      // Max 5 files per request
    },
    abortOnLimit: true,
    responseOnLimit: "File too large or too many files"
}));

// Input validation and sanitization helpers
const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 255;
};

const validatePassword = (password) => {
    return password && password.length >= 6 && password.length <= 128;
};

const sanitizeInput = (input) => {
    if (typeof input !== 'string') return input;
    return input.trim().substring(0, 255);
};

// Generate unique filename to prevent conflicts between users
const generateUniqueFilename = (originalName) => {
    const timestamp = Date.now();
    const random = Math.floor(Math.random() * 10000);
    const ext = path.extname(originalName);
    const name = path.basename(originalName, ext).replace(/[^a-zA-Z0-9]/g, '_');
    return `${timestamp}_${random}_${name}${ext}`;
};

// Serve HTML files
app.get("/", function (req, resp) {
    resp.sendFile(path.join(process.cwd(), "public", "index.html"));
});

app.get('/buyer', (req, res) => {
    res.sendFile(__dirname + '/buyer.html');
});

// ====================== Sign Up =====================
app.post("/create-Account", authLimiter, function (req, resp) {
    const email = sanitizeInput(req.body.someEmail);
    const password = req.body.somePwd;

    // Validate inputs
    if (!validateEmail(email)) {
        return resp.status(400).send("Invalid email format");
    }

    if (!validatePassword(password)) {
        return resp.status(400).send("Password must be 6-128 characters long");
    }

    // Use transaction to prevent race conditions during user registration
    dbCon.getConnection((err, connection) => {
        if (err) {
            console.error("Connection error:", err);
            return resp.status(500).send("Server error occurred");
        }

        connection.beginTransaction((err) => {
            if (err) {
                connection.release();
                console.error("Transaction error:", err);
                return resp.status(500).send("Server error occurred");
            }

            // Check if email exists with row lock to prevent duplicate registrations
            connection.query(
                "SELECT email FROM register WHERE email = ? FOR UPDATE",
                [email],
                function (err, results) {
                    if (err) {
                        return connection.rollback(() => {
                            connection.release();
                            console.error("Error checking email existence:", err);
                            resp.status(500).send("Server error occurred");
                        });
                    }

                    if (results.length > 0) {
                        return connection.rollback(() => {
                            connection.release();
                            resp.status(400).send("Email already registered");
                        });
                    }

                    // Hash password before storing
                    bcrypt.hash(password, 10, function (err, hashedPassword) {
                        if (err) {
                            return connection.rollback(() => {
                                connection.release();
                                console.error("Error hashing password:", err);
                                resp.status(500).send("Server error occurred");
                            });
                        }

                        // Insert new user
                        connection.query(
                            "INSERT INTO register (email, pwd, name, company_name, company_details, address, country, state, city, isd, number, dos, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_DATE(), 1)",
                            [
                                email,
                                hashedPassword,
                                sanitizeInput(req.body.someName),
                                sanitizeInput(req.body.someCompany_name),
                                sanitizeInput(req.body.someCompany_detail),
                                sanitizeInput(req.body.someAddress),
                                sanitizeInput(req.body.someCountry),
                                sanitizeInput(req.body.someState),
                                sanitizeInput(req.body.someCity),
                                sanitizeInput(req.body.someISD),
                                sanitizeInput(req.body.someNumber)
                            ],
                            function (err) {
                                if (err) {
                                    return connection.rollback(() => {
                                        connection.release();
                                        console.error("Error inserting data:", err);
                                        resp.status(500).send("Error saving record: " + err.message);
                                    });
                                }

                                // Commit transaction
                                connection.commit((err) => {
                                    if (err) {
                                        return connection.rollback(() => {
                                            connection.release();
                                            console.error("Error committing transaction:", err);
                                            resp.status(500).send("Server error occurred");
                                        });
                                    }

                                    connection.release();
                                    resp.send("Record saved and email sent successfully!");

                                    // Send welcome email (without password for security)
                                    const transporter = nodemailer.createTransport({
                                        service: 'gmail',
                                        auth: {
                                            user: process.env.EMAIL_USER,
                                            pass: process.env.EMAIL_PASS
                                        }
                                    });

                                    const options = {
                                        from: process.env.EMAIL_USER || "mechswap09@gmail.com",
                                        to: email,
                                        subject: "# Welcome to MechSwap - Your Registration is Complete!",
                                        text: "You have successfully signed up",
                                        html: `<h1>Dear ${sanitizeInput(req.body.someName)},</h1><br><br>Thank you for registering with MechSwap, your go-to platform for machinery trading. We're excited to have you on board!
<br><br>Your account has been successfully created with the following details:<br><br>Login ID: ${email}<br>Please use the password you chose during registration to log in.<br><br>To get started:<br>
1. Log in to your account <br>
2. Start browsing or listing your industrial machinery<br><br>If you have any questions or need assistance, please don't hesitate to contact our support team at ${process.env.EMAIL_USER || 'mechswap09@gmail.com'}.
<br><br>Happy trading!<br><br>Best regards,<br>  
The MechSwap Team.<br><br>---<br><br>*This email was sent to ${email}. If you didn't create an account on MechSwap, please ignore this email or contact us immediately.*`
                                    };

                                    transporter.sendMail(options, function (err, info) {
                                        if (err) {
                                            console.error("Error sending email:", err);
                                        } else {
                                            console.log("Email sent: " + info.response);
                                        }
                                    });
                                });
                            }
                        );
                    });
                }
            );
        });
    });
});

//===================== Forgot Password =====================
app.post("/forgot-Account", authLimiter, function (req, resp) {
    const email = sanitizeInput(req.body.someEmail);

    if (!validateEmail(email)) {
        return resp.status(400).send("Invalid email format");
    }

    const lowerCaseEmail = email.toLowerCase();

    // Check if email exists (don't send actual password for security)
    dbCon.query("SELECT email, name FROM register WHERE LOWER(email) = ?", [lowerCaseEmail], function (err, results) {
        if (err) {
            console.error("Error checking email existence:", err);
            return resp.status(500).send("Server error occurred");
        }

        console.log("Query results: ", results);

        if (results.length === 0) {
            return resp.status(400).send("Email not registered");
        }

        resp.send("Password reset instructions sent to your email!");

        const userName = results[0].name;

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        const options = {
            from: process.env.EMAIL_USER || "mechswap09@gmail.com",
            to: lowerCaseEmail,
            subject: "# MechSwap - Password Reset Request",
            text: "Password reset request",
            html: `<h1>Dear ${userName}</h1><br>We received a request to reset the password for your MechSwap account.<br><br>
<b>Login ID: ${lowerCaseEmail}</b><br><br>
To reset your password, please contact our support team at ${process.env.EMAIL_USER || 'mechswap09@gmail.com'} with your account details.<br><br>
If you didn't make this request, please ignore this email.<br><br>
Best regards, <br>The MechSwap Team<br><br>---<br><br>*This email was sent to ${lowerCaseEmail}. If you didn't request a password reset, please secure your account and contact us immediately.*`
        };

        transporter.sendMail(options, function (err, info) {
            if (err) {
                console.error("Error sending email:", err);
            } else {
                console.log("Email sent: " + info.response);
            }
        });
    });
});

// ====================== Log In - FIXED FOR BOTH HASHED AND PLAIN TEXT =====================
app.get("/do-login", authLimiter, function (req, resp) {
    const email = sanitizeInput(req.query.someEmail);
    const password = req.query.somePwd;

    if (!validateEmail(email) || !password) {
        return resp.send("INVALID EMAIL OR PASSWORD");
    }

    dbCon.query(
        "SELECT * FROM register WHERE email = ?",
        [email],
        function (err, resultJSONTable) {
            if (err) {
                console.error(err);
                return resp.status(500).send("Server error");
            }

            if (resultJSONTable.length > 0) {
                const user = resultJSONTable[0];
                const storedPassword = user.pwd;

                // Check if password is hashed (starts with $2b$) or plain text
                if (storedPassword.startsWith('$2b$')) {
                    // Password is hashed - use bcrypt to compare
                    bcrypt.compare(password, storedPassword, function (err, isMatch) {
                        if (err) {
                            console.error("Error comparing password:", err);
                            return resp.status(500).send("Server error");
                        }

                        if (isMatch) {
                            switch (user.status) {
                                case 1:
                                    resp.send("OK");
                                    break;
                                case 2:
                                    resp.send("ADMIN");
                                    break;
                                default:
                                    resp.send("USER BLOCKED");
                            }
                        } else {
                            resp.send("INVALID EMAIL OR PASSWORD");
                        }
                    });
                } else {
                    // Password is plain text - direct comparison (for existing users)
                    if (password === storedPassword) {
                        // TODO: Consider migrating this user's password to hashed version
                        switch (user.status) {
                            case 1:
                                resp.send("OK");
                                break;
                            case 2:
                                resp.send("ADMIN");
                                break;
                            default:
                                resp.send("USER BLOCKED");
                        }
                    } else {
                        resp.send("INVALID EMAIL OR PASSWORD");
                    }
                }
            } else {
                resp.send("INVALID EMAIL OR PASSWORD");
            }
        }
    );
});

// ====================== Fetch User Data =====================
app.get("/json-record", function (req, resp) {
    const email = sanitizeInput(req.query.kuchemail);

    if (!validateEmail(email)) {
        return resp.status(400).send("Invalid email");
    }

    dbCon.query(
        "SELECT email, name, company_name, company_details, address, country, state, city, isd, number, dos, status FROM register WHERE email = ?",
        [email],
        function (err, resultJSONKuch) {
            if (err) {
                console.error("Error fetching user data:", err);
                return resp.status(500).send("Server error");
            }
            resp.json(resultJSONKuch);
        }
    );
});

// ====================== Update User =====================
app.post("/update-user", function (req, resp) {
    const { email, companyName, companyDetail, userName, userAddress, userCountry, userState, userCity, userISD, userMobile } = req.body;

    if (!validateEmail(email)) {
        return resp.status(400).send("Invalid email");
    }

    const query = `UPDATE register SET company_name = ?, company_details = ?, name = ?, address = ?, country = ?, state = ?, city = ?, isd = ?, number = ? WHERE email = ?`;
    const values = [
        sanitizeInput(companyName),
        sanitizeInput(companyDetail),
        sanitizeInput(userName),
        sanitizeInput(userAddress),
        sanitizeInput(userCountry),
        sanitizeInput(userState),
        sanitizeInput(userCity),
        sanitizeInput(userISD),
        sanitizeInput(userMobile),
        email
    ];

    dbCon.query(query, values, function (err) {
        if (err) {
            console.error("Error updating user:", err);
            return resp.status(500).send("Server error");
        }
        resp.send("User details updated successfully");
    });
});

// ====================== Change Password =====================
app.post("/change-password", function (req, resp) {
    const { currentPassword, newPassword, UserUserEmail } = req.body;

    if (!validateEmail(UserUserEmail) || !validatePassword(newPassword)) {
        return resp.status(400).send("Invalid input");
    }

    dbCon.query("SELECT pwd FROM register WHERE email = ?", [UserUserEmail], function (err, result) {
        if (err) {
            console.error("Error fetching user password:", err);
            return resp.status(500).send("Server error");
        }

        if (result.length === 0) {
            return resp.status(404).send("User not found");
        }

        const storedPassword = result[0].pwd;

        // Check if current password is hashed or plain text
        if (storedPassword.startsWith('$2b$')) {
            // Current password is hashed - use bcrypt to compare
            bcrypt.compare(currentPassword, storedPassword, function (err, isMatch) {
                if (err) {
                    console.error("Error comparing password:", err);
                    return resp.status(500).send("Server error");
                }

                if (!isMatch) {
                    return resp.status(401).send("Current password is incorrect");
                }

                // Hash new password
                bcrypt.hash(newPassword, 10, function (err, hashedNewPassword) {
                    if (err) {
                        console.error("Error hashing new password:", err);
                        return resp.status(500).send("Server error");
                    }

                    dbCon.query("UPDATE register SET pwd = ? WHERE email = ?", [hashedNewPassword, UserUserEmail], function (err) {
                        if (err) {
                            console.error("Error updating password:", err);
                            return resp.status(500).send("Server error");
                        }
                        resp.send("Password updated successfully");
                    });
                });
            });
        } else {
            // Current password is plain text - direct comparison
            if (currentPassword !== storedPassword) {
                return resp.status(401).send("Current password is incorrect");
            }

            // Hash new password
            bcrypt.hash(newPassword, 10, function (err, hashedNewPassword) {
                if (err) {
                    console.error("Error hashing new password:", err);
                    return resp.status(500).send("Server error");
                }

                dbCon.query("UPDATE register SET pwd = ? WHERE email = ?", [hashedNewPassword, UserUserEmail], function (err) {
                    if (err) {
                        console.error("Error updating password:", err);
                        return resp.status(500).send("Server error");
                    }
                    resp.send("Password updated successfully");
                });
            });
        }
    });
});

// ====================== Add Product =====================
const uploadPath = path.join(__dirname, 'public', 'uploads');

app.post('/add-product', (req, res) => {
    const productId = sanitizeInput(req.body.some_product_id);
    const email = sanitizeInput(req.body.some_Email);

    // Validate required fields
    if (!productId || !validateEmail(email) || !req.body.some_product_name) {
        return res.status(400).send("Missing required fields");
    }

    const usageType = sanitizeInput(req.body.some_usage_type);
    const productName = sanitizeInput(req.body.some_product_name);
    const modelNo = sanitizeInput(req.body.some_model_no);
    const countryMfg = sanitizeInput(req.body.some_country_mfg);
    const capacity = sanitizeInput(req.body.some_capacity);
    const warranty = sanitizeInput(req.body.some_warranty);
    const usageYears = sanitizeInput(req.body.some_usage_years);
    const specification = sanitizeInput(req.body.some_specification);
    const currency = sanitizeInput(req.body.some_currency);
    const price = req.body.some_price;
    const quantity = req.body.some_quantity;
    const categoryVal = sanitizeInput(req.body.some_categoryVal);
    const category = sanitizeInput(req.body.some_category);
    const sub_category = sanitizeInput(req.body.some_subcategory);

    // Handle file uploads with unique naming to prevent conflicts
    const mainImage = req.files?.some_main_image;
    const image1 = req.files?.some_image1;
    const image2 = req.files?.some_image2;

    const filePromises = [];

    if (mainImage) {
        filePromises.push(new Promise((resolve, reject) => {
            const uniqueName = generateUniqueFilename(mainImage.name);
            mainImage.mv(path.join(uploadPath, uniqueName), (err) => {
                if (err) return reject(err);
                resolve(uniqueName);
            });
        }));
    }
    if (image1) {
        filePromises.push(new Promise((resolve, reject) => {
            const uniqueName = generateUniqueFilename(image1.name);
            image1.mv(path.join(uploadPath, uniqueName), (err) => {
                if (err) return reject(err);
                resolve(uniqueName);
            });
        }));
    }
    if (image2) {
        filePromises.push(new Promise((resolve, reject) => {
            const uniqueName = generateUniqueFilename(image2.name);
            image2.mv(path.join(uploadPath, uniqueName), (err) => {
                if (err) return reject(err);
                resolve(uniqueName);
            });
        }));
    }

    Promise.all(filePromises)
        .then(fileNames => {
            const [mainImageName, image1Name, image2Name] = fileNames;

            // Insert data into MySQL database
            const query = `INSERT INTO products (productID, email, usage_type, product_name, product_model, country_mfg, capacity, warranty, usage_years, specification, currency, price, quantity, main_image, image1, image2, category_val, category, sub_category)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

            dbCon.query(query, [
                productId, email, usageType, productName, modelNo, countryMfg, capacity, warranty, usageYears,
                specification, currency, price, quantity, mainImageName, image1Name, image2Name, categoryVal, category, sub_category
            ], (err, results) => {
                if (err) {
                    console.error('Error inserting product:', err);
                    return res.status(500).send('Error adding product');
                }
                res.send('Product added successfully');
            });
        })
        .catch(err => {
            console.error('Error handling file uploads:', err);
            res.status(500).send('Error uploading files: ' + err.message);
        });
});

//=========================== Manage Product Detail ============================= 
app.get("/get-angular-all-records", function (req, resp) {
    const email = sanitizeInput(req.query.email);

    if (!validateEmail(email)) {
        return resp.status(400).send("Invalid email");
    }

    dbCon.query("SELECT * FROM products WHERE email = ?", [email], function (err, resultTableJSON) {
        if (err) {
            console.error("Error fetching products:", err);
            return resp.status(500).send("Error fetching records");
        }
        resp.json(resultTableJSON);
    });
});

//======================== Action Remove ======================================
app.get("/do-angular-remove", function (req, resp) {
    const productID = sanitizeInput(req.query.productID);

    if (!productID) {
        return resp.status(400).send("Product ID is required");
    }

    dbCon.query("DELETE FROM products WHERE productID = ?", [productID], function (err, result) {
        if (err) {
            console.error("Error removing product:", err);
            return resp.status(500).send("Server error");
        }

        if (result.affectedRows === 1) {
            resp.send("Product Removed Successfully!!");
        } else {
            resp.send("Product not found");
        }
    });
});

// ====================== Additional Routes =====================
app.get('/product-status', (req, res) => {
    const email = sanitizeInput(req.query.txtEmail1);

    if (!validateEmail(email)) {
        return res.status(400).send("Invalid email");
    }

    const query = `SELECT COUNT(*) AS totalPosted FROM products WHERE email = ?`;

    dbCon.query(query, [email], (err, results) => {
        if (err) {
            console.error('Error fetching product status:', err);
            return res.status(500).send('Error fetching product status');
        }
        res.json(results[0]);
    });
});

app.get("/get-angular-buyer-records", function (req, resp) {
    dbCon.query(`
        SELECT category, sub_category, COUNT(*) as count 
        FROM products 
        GROUP BY category, sub_category
    `, function (err, resultTableJSON) {
        if (err) {
            console.error("Error fetching buyer records:", err);
            return resp.status(500).send("Server error");
        }
        resp.json(resultTableJSON);
    });
});

app.get("/get-angular-variety-records", function (req, resp) {
    const sub_category = sanitizeInput(req.query.sub_category);
    const category = sanitizeInput(req.query.category);

    if (!sub_category || !category) {
        return resp.status(400).send("Category and sub-category are required");
    }

    const query = "SELECT * FROM products WHERE sub_category = ? AND category = ?";

    dbCon.query(query, [sub_category, category], function (err, resultTable) {
        if (err) {
            console.error("Error fetching variety records:", err);
            return resp.status(500).send("Server error");
        }
        resp.json(resultTable);
    });
});

app.get("/get-angular-product-records", function (req, resp) {
    const productID = sanitizeInput(req.query.productID);

    if (!productID) {
        return resp.status(400).send("Product ID is required");
    }

    const query = "SELECT * FROM products WHERE productID = ?";

    dbCon.query(query, [productID], function (err, resultTable) {
        if (err) {
            console.error("Error fetching product records:", err);
            return resp.status(500).send("Server error");
        }
        resp.json(resultTable);
    });
});

app.get("/get-angular-user-records", function (req, resp) {
    const email = sanitizeInput(req.query.email);

    if (!validateEmail(email)) {
        return resp.status(400).send("Invalid email");
    }

    const query = "SELECT email, name, company_name, company_details, address, country, state, city, isd, number, dos, status FROM register WHERE email = ?";

    dbCon.query(query, [email], function (err, resultTable) {
        if (err) {
            console.error("Error fetching user records:", err);
            return resp.status(500).send("Server error");
        }
        resp.json(resultTable);
    });
});

app.get("/productUser-record", function (req, resp) {
    const email = sanitizeInput(req.query.someemail);

    if (!validateEmail(email)) {
        return resp.status(400).send("Invalid email");
    }

    dbCon.query(
        "SELECT email, name, company_name, company_details, address, country, state, city, isd, number, dos, status FROM register WHERE email = ?",
        [email],
        function (err, resultJSONKuch) {
            if (err) {
                console.error("Error fetching product user record:", err);
                return resp.status(500).send("Server error");
            }
            resp.json(resultJSONKuch);
        }
    );
});

app.post("/buyer-Account", function (req, resp) {
    const email = sanitizeInput(req.body.somebuyerEmail);

    if (!validateEmail(email)) {
        return resp.status(400).send("Invalid email");
    }

    console.log("New buyer registration:", email);

    dbCon.query(
        "INSERT INTO buyer (buyer_productID, buyer_email, buyer_name, buyer_country, buyer_state, buyer_city, buyer_ISD, buyer_number, buyer_dos) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_DATE())",
        [
            sanitizeInput(req.body.somebuyerProductID),
            email,
            sanitizeInput(req.body.somebuyerName),
            sanitizeInput(req.body.somebuyerCountry),
            sanitizeInput(req.body.somebuyerState),
            sanitizeInput(req.body.somebuyerCity),
            sanitizeInput(req.body.somebuyerISD),
            sanitizeInput(req.body.somebuyerNumber)
        ],
        function (err) {
            if (err) {
                console.error("Error inserting buyer data:", err);
                return resp.status(500).send("Error saving record: " + err.message);
            }
            resp.send("Record saved");

            // Send notification email
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });

            const options = {
                from: process.env.EMAIL_USER || "mechswap09@gmail.com",
                to: process.env.EMAIL_USER || "mechswap09@gmail.com",
                subject: "New Buyer Registration",
                text: "New buyer information",
                html: `<h1>New Buyer Registration</h1><br><br>
                Buyer Email: ${email}<br>
                Product ID: ${sanitizeInput(req.body.somebuyerProductID)}<br>
                Phone Number: ${sanitizeInput(req.body.somebuyerNumber)}<br>
                Name: ${sanitizeInput(req.body.somebuyerName)}`
            };

            transporter.sendMail(options, function (err, info) {
                if (err) {
                    console.error("Error sending notification email:", err);
                } else {
                    console.log("Notification email sent: " + info.response);
                }
            });
        }
    );
});

// Start the server
const PORT = process.env.PORT || 2025;
app.listen(PORT, function () {
    console.log(`Server started on port ${PORT}`);
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    dbCon.end(() => {
        console.log('Database connections closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully');
    dbCon.end(() => {
        console.log('Database connections closed');
        process.exit(0);
    });
});