const express = require("express");
const dotenv = require("dotenv").config();
const { Pool } = require('pg');
const jwt = require("jsonwebtoken")

const app = express();
app.use(express.json());

// PostgreSQL connection pool configuration
const pool = new Pool({
    host: process.env.HOST,
    port: process.env.PORT,
    user: process.env.USER,
    password: process.env.PASSWORD,
    database: process.env.DATABASE,
    max: 10,                      // Maximum number of connections in the pool
    idleTimeoutMillis: 30000,     // Close idle connections after 30 seconds
    connectionTimeoutMillis: 2000,
    ssl:{
        rejectUnauthorized: false,
        // ca: fs.readFileSync('/path/to/server-certificates/root.crt').toString(),
      },
});

app.get('/',async(req,res)=>{
    try{
        res.send("Hello world");
    }catch(err){
        res.status(500).json({ message: 'Internal server error' });
    }
})

app.post('/login', async (req, res) => {
    const { mobile, password } = req.body;

    // Ensure mobile and password are provided
    if (!mobile || !password) {
        return res.status(400).json({ message: 'mobile and password are required' });
    }

    try {
        // Call the PostgreSQL function to validate the vendor
        const result = await pool.query(
            'SELECT validate_vendor($1, $2) AS response',
            [mobile, password]
        );

        // Extract the JSON response from the result
        const loginResponse = result.rows[0].response;

        // Check the status from the response
        if (loginResponse.status === 'error') {
            return res.status(401).json({ message: loginResponse.message });
        }

        const vendor = loginResponse.vendor

        // Create JWT token
        const payload = {
            id: vendor.id,
            mobile: vendor.mobile,
            name: vendor.name
        }

        // Define JWT secret key (should be stored in environment variables for security)
        const secretKey = process.env.JWT_SECRET || 'ABCD';

         // Generate JWT token,
         const token = jwt.sign(payload,secretKey);

        // Send the success response with vendor details
        res.status(200).json({
            statusCode: 200,
            message: loginResponse.message,
            vendor: vendor,
            token: token
        })
        // res.json({
        //     message: loginResponse.message,
        //     vendor: loginResponse.vendor
        // });
    } catch (err) {
        console.error('Query error:', err.stack);
        res.status(500).json({ message: 'Error executing query' });
    }
});

app.get('/vendor/:id', async (req, res) => {
    const vendorId = req.params.id;

    try {
        // Query the function directly to get vendor details by ID
        const result = await pool.query('SELECT get_vendor_by_id($1)', [vendorId]);
        
        // Check if result exists
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Vendor not found' });
        }

        // Return the JSON result with vendor details
        res.json(result.rows[0].get_vendor_by_id);
    } catch (err) {
        // console.error('Query error:', err.stack);
        res.status(500).send({ message: 'Error executing query' });
    }
});


// Close the pool when the server is shutting down
process.on('SIGINT', () => {
    console.log("Shutting down the server...");
    pool.end(() => {
        console.log("Connection pool closed");
        process.exit(0);
    });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});
