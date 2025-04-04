const dotenv = require("dotenv").config();
const express = require("express");
const { Pool } = require('pg');
const jwt = require("jsonwebtoken")

const app = express();
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// PostgreSQL connection pool configuration
const pool = new Pool({
    host: process.env.HOST,
    port: process.env.PORT,
    user: process.env.USER1,
    password: process.env.PASSWORD,
    database: process.env.DATABASE,
    max: 10,                      // Maximum number of connections in the pool
    idleTimeoutMillis: 30000,     // Close idle connections after 30 seconds
    connectionTimeoutMillis: 2000,
    // ssl: false
    ssl: {
        rejectUnauthorized: false,
        // ca: fs.readFileSync('/path/to/server-certificates/root.crt').toString(),
    },
});

app.get('/', async (req, res) => {
    try {
        res.send("Hello world");
        console.log(process.env.HOST);
        console.log(process.env.PORT);
        console.log(process.env.USER1);
        console.log(process.env.PASSWORD);
        console.log(process.env.DATABASE);
    } catch (err) {
        res.status(500).json({ message: 'Internal server error' });
    }
})

const verifyToken = (allowedRoles) => {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({
                status_code: 401,
                message: 'Access denied. No token provided.'
            });
        }

        const token = authHeader.replace('Bearer ', '');
        try {
            const secretKey = process.env.JWT_SECRET || 'ABCD';
            const decoded = jwt.verify(token, secretKey);

            // Attach the decoded token payload to the request object
            req.user = decoded;

            // Check if the user's role is allowed
            if (!allowedRoles.includes(decoded.userType)) {
                return res.status(403).json({
                    status_code: 403,
                    message: 'Access denied. You do not have permission to perform this action.',
                });
            }

            // Proceed to the next middleware or route handler
            next();
        } catch (err) {
            return res.status(401).json({
                status_code: 401,
                message: 'Invalid or expired token.',
            });
        }
    };
};


app.post('/login', async (req, res) => {
    const { mobile, userType } = req.body;

    // Validate input
    if (!mobile || !userType) {
        return res.status(400).json({
            status_code: 400,
            message: 'Mobile number and user type are required',
        });
    }

    try {
        // Call the PostgreSQL function to validate the user
        const result = await pool.query(
            'SELECT validate_user($1, $2) AS response',
            [mobile, userType]
        );

        // Extract the JSON response from the result
        const loginResponse = result.rows[0].response;

        // Check the status from the response
        if (loginResponse.status === 'error') {
            let errorMessage = 'User not found';
            if (userType === 'vendor') {
                errorMessage = 'Vendor not found. Please sign up.';
            } else if (userType === 'employee') {
                errorMessage = 'Employee not found. Please contact your vendor for login.';
            } else if (userType === 'customer') {
                errorMessage = 'Customer not found. Please contact your vendor or their staff for login.';
            }

            return res.status(404).json({
                status_code: 404,
                message: errorMessage,
            });
        }

        // User details from the response
        const user = loginResponse.user;

        // Conditionally remove the connected_vendors field for vendors
        if (userType === 'vendor' && !user.connected_vendors) {
            delete user.connected_vendors;
        }

        // Create JWT token
        const payload = {
            id: user.id,
            mobile: user.mobile,
            name: user.name,
            userType: userType,
            connectedVendors: user.connected_vendors || [],
        };

        const secretKey = process.env.JWT_SECRET || 'ABCD';
        const token = jwt.sign(payload, secretKey, { expiresIn: '1d' });

        // Send success response with token
        return res.status(200).json({
            status_code: 200,
            message: loginResponse.message,
            user,
            token,
        });
    } catch (err) {
        console.error('Query error:', err.stack);
        return res.status(500).json({
            status_code: 500,
            message: 'Error executing query',
        });
    }
});



//create vendors
app.post('/vendors', async (req, res) => {
    const { name, email, mobile, address, password } = req.body;

    try {
        const result = await pool.query({
            text: 'SELECT * FROM create_vendor($1,$2,$3,$4,$5)',
            values: [name, email, mobile, address, password]
        });
        res.status(201).json({
            statusCode: 201,
            message: 'success',
            data: result.rows[0],
        });
    } catch (err) {
        res.status(500).json({
            statusCode: 500,
            message: 'Internal server',
            error: err.message,
        });
    }
})

// Get All Vendors
app.get('/vendors', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM get_all_vendors()');

        res.status(200).json({
            statusCode: 200,
            message: 'success',
            data: result.rows,
        });
    } catch (error) {
        console.error('Error fetching vendors:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to fetch vendors',
            error: error.message,
        });
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
        console.error('Query error:', err.stack);
        res.status(500).send({ message: 'Error executing query' });
    }
});

//get vendor details by id
app.get('/vendor', verifyToken(['vendor']), async (req, res) => {
    const vendorId = req.user.id;

    try {
        // Query the function directly to get vendor details by ID
        const result = await pool.query(`
            SELECT * FROM vendors 
            WHERE id = $1`
            , [vendorId]);

        // Check if result exists
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Vendor not found' });
        }

        // Return the JSON result with vendor details
        res.json({ statusCode: 200, message: "success", data: result.rows[0] });
    } catch (err) {
        console.error('Query error:', err.stack);
        res.status(500).send({ message: 'Internal server error' });
    }
});

//update vendor details (Profile api)
app.put('/vendor', verifyToken(['vendor']), async (req, res) => {
    const vendorId = req.user.id;

    const {
        name, email, mobile, address, business_name, gst_number, business_image, qr_code_image
    } = req.body;

    try {
        // Query the function directly to get vendor details by ID
        const result = await pool.query({
            text: `
            UPDATE vendors 
            SET
                name = $1,
                email = $2,
                mobile = $3,
                address = $4,
                business_name = $5,
                gst_number = $6,
                business_image = $7,
                qr_code_image = $8,
                updated_by = $9,
                updated_at = NOW()  
            WHERE
                id = $10
            RETURNING id, name, email, mobile, address, business_name, gst_number, business_image, qr_code_image, updated_by, updated_at;
            `
            , values: [name, email, mobile, address, business_name, gst_number, business_image, qr_code_image, vendorId, vendorId]
        });


        // Check if result exists
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Vendor not found' });
        }

        // Return the JSON result with vendor details
        res.json({ statusCode: 200, message: "Profile updated successfully", data: result.rows[0] });
    } catch (err) {
        console.error('Query error:', err.stack);
        res.status(500).send({ message: 'Internal server error' });
    }
});

// Update Vendor
app.put('/vendors/:vendorId', async (req, res) => {
    const vendorId = parseInt(req.params.vendorId);
    const { name, email, mobile, address } = req.body;

    try {
        const result = await pool.query({
            text: 'SELECT * FROM update_vendor($1, $2, $3, $4, $5)',
            values: [vendorId, name, email, mobile, address],
        });

        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'Vendor not found',
            });
        }

        res.status(200).json({
            statusCode: 200,
            message: 'Vendor updated successfully',
            vendor: result.rows[0],
        });
    } catch (error) {
        console.error('Error updating vendor:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to update vendor',
            error: error.message,
        });
    }
});

// Delete Vendor
app.delete('/vendors/:vendorId', async (req, res) => {
    const vendorId = parseInt(req.params.vendorId);

    try {
        const result = await pool.query({
            text: 'SELECT * FROM delete_vendor($1)',
            values: [vendorId],
        });

        if (result.rows[0].message === 'Vendor not found') {
            return res.status(404).json({
                statusCode: 404,
                message: 'Vendor not found',
            });
        }

        res.status(200).json({
            statusCode: 200,
            message: result.rows[0].message,
            data: {
                id: result.rows[0].deleted_vendor_id,
                name: result.rows[0].deleted_vendor_name,
            },
        });
    } catch (error) {
        console.error('Error deleting vendor:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to delete vendor',
            error: error.message,
        });
    }
});

//CUSTOMERS (Add by Vendor App)
app.post('/vendors/customers', verifyToken(['vendor']), async (req, res) => {
    const vendorId = parseInt(req.user.id);
    const created_by = req.user.id;
    const { name, email, mobile, address, status = 'active' } = req.body; // New field

    try {
        const result = await pool.query({
            text: 'SELECT * FROM create_customer($1, $2, $3, $4, $5, $6, $7)',
            values: [vendorId, name, email, mobile, address, status, created_by], // Automatically handles new fields
        });
        res.status(201).json({
            statusCode: 201,
            message: 'Customer added successfully',
            data: result.rows[0],
        });
    } catch (err) {
        console.error('Error creating customer:', err.stack);
        res.status(500).json({
            statusCode: 500,
            message: 'Internal server error',
            error: err.message,
        });
    }
});

// Get Customer by ID
app.get('/vendors/:vendorId/customers/:customerId', async (req, res) => {
    const vendorId = parseInt(req.params.vendorId);
    const customerId = parseInt(req.params.customerId);

    try {
        const result = await pool.query({
            text: 'SELECT * FROM get_customer_by_id($1)',
            values: [customerId],
        });

        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'Customer not found',
            });
        }

        res.status(200).json({
            statusCode: 200,
            message: 'success',
            customer: result.rows[0],
        });
    } catch (error) {
        console.error('Error fetching customer:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to fetch customer',
            error: error.message,
        });
    }
});

// Get All Customers (for a specific vendor)
app.get('/vendors/:vendorId/customers', verifyToken(['vendor', 'employee']), async (req, res) => {
    try {
        const { vendorId } = req.params;
        const search = req.query.search || ''; // Get search term or default to empty

        const result = await pool.query(
            `SELECT * FROM customers 
             WHERE vendor_id = $1 
             AND status='active' 
             AND (name ILIKE $2 OR mobile ILIKE $2)
             ORDER BY name ASC`,
            [vendorId, `%${search}%`]
        );

        res.status(result.rows.length ? 200 : 404).json({
            statusCode: result.rows.length ? 200 : 404,
            message: result.rows.length ? 'success' : 'No matching customers found',
            data: result.rows,
        });

    } catch (error) {
        console.error('Error fetching customers:', error);
        res.status(500).json({ statusCode: 500, message: 'Failed to fetch customers', error: error.message });
    }
});

// app.get('/vendor/:vendorId/customers',verifyToken(['vendor','employee']), async (req, res) => {
//     const vendorId = parseInt(req.params.vendorId || req.user.id);

//     try {
//         if (isNaN(vendorId)) {
//             return res.status(400).json({
//                 statusCode: 400,
//                 message: 'Invalid vendor ID',
//             });
//         }

//         // Fetch customer data for the given vendorId
//         const result = await pool.query({
//             text: 'SELECT * FROM get_customer_list($1)',
//             values: [vendorId], // Only pass vendorId as a parameter
//         });

//         if (result.rows.length === 0) {
//             return res.status(404).json({
//                 statusCode: 404,
//                 message: 'No customers found for this vendor',
//                 data: [],
//             });
//         }

//         // Return the fetched customer data
//         res.status(200).json({
//             statusCode: 200,
//             message: 'Customers retrieved successfully',
//             data: result.rows, // Return the full result set
//         });
//     } catch (err) {
//         console.error('Error fetching customer data:', err.stack);
//         res.status(500).json({
//             statusCode: 500,
//             message: 'Internal server error',
//             error: err.message,
//         });
//     }
// });


// Update Customer
app.put('/vendors/customers/:customerId', verifyToken(['vendor']), async (req, res) => {
    const customerId = parseInt(req.params.customerId);
    const updated_by = parseInt(req.user.id);
    const { name, email, mobile, address, status } = req.body;

    try {
        const result = await pool.query({
            text: 'SELECT * FROM update_customer($1, $2, $3, $4, $5, $6, $7)',
            values: [customerId, name, email, mobile, address, status, updated_by],
        });

        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'Customer not found',
            });
        }

        res.status(200).json({
            statusCode: 200,
            message: 'Customer updated successfully',
            data: result.rows[0],
        });
    } catch (error) {
        console.error('Error updating customer:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to update customer',
            error: error.message,
        });
    }
});

// Delete Customer API
app.delete('/vendors/customers/:customerId', async (req, res) => {
    const customerId = parseInt(req.params.customerId);

    try {
        // Call the PostgreSQL function to delete the customer
        const result = await pool.query({
            text: 'SELECT * FROM delete_customer($1)',
            values: [customerId]
        });

        // Return the result
        res.status(200).json({
            statusCode: 200,
            message: result.rows[0].message,
            data: {
                deleted_customer_id: result.rows[0].deleted_customer_id,
                deleted_customer_name: result.rows[0].deleted_customer_name
            }
        });
    } catch (err) {
        console.error('Error deleting customer:', err.stack);
        res.status(500).json({
            statusCode: 500,
            message: 'Internal server error',
            error: err.message
        });
    }
});


//PRODUCTS
//add product
app.post('/products', verifyToken(['vendor']), async (req, res) => {
    const vendor_id = req.user.id;
    const created_by = req.user.id;
    const { name, price_per_unit, unit, status = 'active' } = req.body;

    if (!name || !price_per_unit || !unit) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const result = await pool.query({
            text: 'SELECT * FROM create_product_func($1, $2, $3, $4, $5, $6)',
            values: [vendor_id, name, price_per_unit, unit, status, created_by],
        });

        res.status(201).json({
            statusCode: 201,
            message: 'Product created successfully',
            data: result.rows[0],
        });
    } catch (error) {
        console.error('Error creating product:', error);
        res.status(500).json({ error: 'Failed to create product' });
    }
});


app.get('/products', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM products');
        if (result.rows.length === 0) {
            return res.status(200).json({
                statusCode: 200,
                message: "No products found",
                data: []
            });
        }

        res.status(200).json({
            statusCode: 200,
            message: "success",
            data: result.rows
        });
    } catch (err) {
        // console.error('Error fetching products:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
})

app.get('/productByVendor', verifyToken(['vendor']), async (req, res) => {
    try {
        // Extract vendor_id from the token
        const vendorId = parseInt(req.user.id);
        // console.log(vendorId)

        // Call the PostgreSQL function with the vendor_id
        const result = await pool.query({
            text: 'SELECT * FROM get_products_by_vendor($1) ORDER BY product_name ASC',
            values: [vendorId],
        });

        // Check if any products were found
        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: "No products found",
                data: []
            });
        }

        // Respond with the retrieved products
        res.status(200).json({
            statusCode: 200,
            message: "success",
            data: result.rows,
        });
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({
            statusCode: 500,
            message: 'Internal server error',
        });
    }
});

//Products by vendor for employee screen
app.get('/employee/productByVendor/:vendorId', verifyToken(['employee']), async (req, res) => {
    try {
        // Extract vendor_id from the token
        const vendorId = parseInt(req.params.vendorId);
        // console.log(vendorId)

        // Call the PostgreSQL function with the vendor_id
        const result = await pool.query({
            text: 'SELECT * FROM get_products_by_vendor($1)',
            values: [vendorId],
        });

        // Check if any products were found
        if (result.rows.length === 0) {
            return res.status(200).json({
                statusCode: 200,
                message: "No products found for this vendor",
                data: [],
            });
        }

        // Respond with the retrieved products
        res.status(200).json({
            statusCode: 200,
            message: "success",
            data: result.rows,
        });
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({
            statusCode: 500,
            message: 'Internal server error',
        });
    }
});


app.delete('/products/:productId', async (req, res) => {
    const productId = parseInt(req.params.productId);
    try {
        const result = await pool.query({
            text: 'SELECT *FROM delete_product($1)',
            values: [productId]
        })
        res.status(200).json({
            message: result.rows[0].message
        })
    } catch (error) {
        //   console.error('Error deleting product:', error);
        res.status(500).json({ error: 'Failed to delete product' });
    }
});

app.put('/products/:productId', verifyToken(['vendor']), async (req, res) => {
    const productId = parseInt(req.params.productId, 10);
    const { name, price_per_unit, unit, status } = req.body;

    try {
        // Extract vendor_id from the token
        const vendorId = parseInt(req.user.id, 10);
        const updated_by = parseInt(req.user.id, 10);

        if (isNaN(productId) || isNaN(vendorId)) {
            return res.status(400).json({
                statusCode: 400,
                message: 'Invalid product ID or vendor ID',
            });
        }

        // Call the PostgreSQL function to update the product
        const result = await pool.query({
            text: 'SELECT * FROM update_product($1, $2, $3, $4, $5, $6, $7)',
            values: [vendorId, productId, name, price_per_unit, unit, status, updated_by],
        });

        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'Product not found or you are not authorized to update this product',
            });
        }

        res.status(200).json({
            statusCode: 200,
            message: 'Product updated successfully',
            data: result.rows[0],
        });
    } catch (error) {
        console.error('Error updating product:', error.stack); // Log the full error stack
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to update product: ' + error.message,
        });
    }
});


// Create Employee
app.post('/employees', verifyToken(['vendor']), async (req, res) => {
    const { name, email, mobile, role, address } = req.body;

    const vendor_id = req.user.id;

    try {
        const result = await pool.query({
            text: 'SELECT * FROM create_employee($1, $2, $3, $4, $5, $6)',
            values: [vendor_id, name, email, mobile, role, address], // Use lowercase 'values'
        });

        res.status(201).json({
            statusCode: 201,
            message: 'success',
            data: result.rows[0], // Return the first row of the result
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to create employee',
            error: err.message,
        });
    }
});

// Get Employee by ID
app.get('/employees/:employeeId', async (req, res) => {
    const employeeId = parseInt(req.params.employeeId);

    try {
        const result = await pool.query({
            text: 'SELECT * FROM get_employee_by_id($1)',
            values: [employeeId],
        });

        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'Employee not found'
            });
        }

        res.status(200).json({
            statusCode: 200,
            message: 'success',
            data: result.rows[0]
        });
    } catch (error) {
        console.error('Error fetching employee:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to fetch employee',
            error: error.message
        });
    }
});

app.get('/vendors/employees', verifyToken(['vendor']), async (req, res) => {
    const vendorId = parseInt(req.user.id);

    try {
        const result = await pool.query({
            text: `SELECT * FROM employees WHERE vendor_id = $1 AND status='active' ORDER BY name ASC`,
            values: [vendorId],
        });

        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'No employees found',
                data: []
            });
        }

        res.status(200).json({
            statusCode: 200,
            message: 'Employees fetched successfully',
            data: result.rows
        });

    } catch (error) {
        console.error('Error fetching employees:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to fetch employees',
            error: error.message
        });
    }
});

// Get All Employees
app.get('/employees', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM get_all_employees()');

        res.status(200).json({
            statusCode: 200,
            message: 'success',
            data: result.rows
        });
    } catch (error) {
        console.error('Error fetching employees:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to fetch employees',
            error: error.message
        });
    }
});

// Update Employee
app.put('/employees/:employeeId', verifyToken(['vendor']), async (req, res) => {
    const employeeId = parseInt(req.params.employeeId, 10);
    const { name, email, mobile, role, address, status } = req.body;
    const updated_by = req.user.id;

    try {
        const result = await pool.query({
            text: 'SELECT * FROM update_employee($1, $2, $3, $4, $5, $6, $7, $8)',
            values: [employeeId, name, email, mobile, role, address, status, updated_by],
        });

        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'Employee not found',
            });
        }

        res.status(200).json({
            statusCode: 200,
            message: 'Employee(staff) updated successfully',
            data: result.rows[0],
        });
    } catch (error) {
        console.error('Error updating employee:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to update employee',
            error: error.message,
        });
    }
});

//employee delete
app.delete('/employees/:employeeId', async (req, res) => {
    const employeeId = parseInt(req.params.employeeId);

    try {
        const result = await pool.query({
            text: 'SELECT * FROM delete_employee($1)',
            values: [employeeId],
        });

        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'Employee not found',
            });
        }

        res.status(200).json({
            statusCode: 200,
            message: 'success',
            data: result.rows[0]
        });
    } catch (err) {
        console.error('Error deleting employee:', err);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to delete employee',
            error: err.message,
        });
    }
});

//Sales apis start
app.post('/sales', verifyToken(['vendor']), async (req, res) => {
    const { customer_id, product_id, quantity, price_per_unit, sale_date } = req.body;
    const vendor_id = req.user.id; // Extract vendor_id from token
    const created_by = req.user.id; // Extract user ID from token
    const total_amount = quantity * price_per_unit;

    try {
        const result = await pool.query({
            text: 'SELECT * FROM insert_sales($1, $2, $3, $4, $5, $6, $7, $8)',
            values: [vendor_id, customer_id, product_id, quantity, price_per_unit, total_amount, sale_date, created_by],
        });

        if (result.rows.length === 0) {
            return res.status(400).json({
                statusCode: 400,
                message: 'Failed to insert sales data',
            });
        }

        res.status(201).json({
            statusCode: 201,
            message: 'Sales data inserted successfully',
            sale: result.rows[0], // Return the inserted sale
        });
    } catch (error) {
        console.error('Error inserting sales data:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to insert sales data',
            error: error.message,
        });
    }
});

//sale by employee
app.post('/employee/sales', verifyToken(['employee']), async (req, res) => {
    const { vendor_id, customer_id, product_id, quantity, price_per_unit, sale_date } = req.body;
    const created_by = req.user.id;       // Extract user ID from token
    // console.log(req.user);
    const total_amount = quantity * price_per_unit;
    try {
        const result = await pool.query({
            text: 'SELECT * FROM insert_sales($1, $2, $3, $4, $5, $6, $7, $8)',
            values: [vendor_id, customer_id, product_id, quantity, price_per_unit, total_amount, sale_date, created_by],
        });

        if (result.rows.length === 0) {
            return res.status(400).json({
                statusCode: 400,
                message: 'Failed to insert sales data',
            });
        }

        res.status(201).json({
            statusCode: 201,
            message: 'Sales data inserted successfully',
            data: result.rows[0], // Return the inserted sale
        });
    } catch (error) {
        console.error('Error inserting sales data:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to insert sales data',
            error: error.message,
        });
    }
});
//monthly sales report
app.post('/sales/customer', verifyToken(['vendor', 'employee', 'customer']), async (req, res) => {
    // const customerId = parseInt(req.params.customerId, 10);
    // const vendorId = req.user.id; // Extract vendor_id from the token
    const { vendorId, customerId, month, year, } = req.body;

    try {
        const result = await pool.query({
            text: `
                SELECT 
                    s.id AS sale_id,
                    s.vendor_id,
                    s.customer_id,
                    c.name AS customer_name,
                    c.mobile AS customer_mobile,
                    s.product_id,
                    p.name AS product_name,
                    s.quantity,
                    s.price_per_unit,
                    s.total_amount,
                    s.created_at,
                    s.created_by,
                    SUM(s.total_amount) OVER () AS total_monthly_expenses
                FROM 
                    sales s
                JOIN 
                    customers c ON s.customer_id = c.id
                JOIN 
                    products p ON s.product_id = p.id
                WHERE 
                    s.customer_id = $1 AND s.vendor_id = $2
                    AND EXTRACT(MONTH FROM s.created_at) = $3
                    AND EXTRACT(YEAR FROM s.created_at) = $4
                ORDER BY 
                    s.created_at DESC
            `,
            values: [customerId, vendorId, month, year],
        });

        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'No sales data found for this customer',
            });
        }

        // Format the date before sending the response
        const salesData = result.rows.map((sale) => ({
            ...sale,
            formatted_date: new Intl.DateTimeFormat('en-US', {
                day: '2-digit',
                month: 'short',
                year: 'numeric',
            }).format(new Date(sale.created_at)), // Format date to "13 Feb, 2024"
        }));

        // const salesData = result.rows;
        const totalMonthlyExpenses = parseFloat(salesData[0].total_monthly_expenses) || 0;

        res.status(200).json({
            statusCode: 200,
            message: 'Sales data retrieved successfully',
            totalMonthlyExpenses, // Return the total of monthly expenses
            sales: salesData, // Return sales data with customer and product details
        });
    } catch (error) {
        console.error('Error retrieving sales data:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to retrieve sales data',
            error: error.message,
        });
    }
});

app.post('/sales/product-summary', verifyToken(['vendor', 'employee', 'customer']), async (req, res) => {
    const { vendorId, customerId, month, year } = req.body;

    try {
        const result = await pool.query({
            text: `
                SELECT
                    p.id AS product_id,
                    p.unit AS product_unit,
                    p.name AS product_name,
                    SUM(s.quantity) AS total_quantity_sold,
                    SUM(s.total_amount) AS total_sales_amount
                FROM 
                    sales s
                JOIN 
                    products p ON s.product_id = p.id
                WHERE
                    s.vendor_id = $1
                    AND s.customer_id = $2
                    AND EXTRACT(MONTH FROM s.sale_date) = $3
                    AND EXTRACT(YEAR FROM s.sale_date) = $4
                GROUP BY 
                    p.id,p.name
                ORDER BY 
                    p.name ASC
            `,
            values: [vendorId, customerId, month, year],
        });

        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'No sales data found for the given criteria',
            });
        }

        res.status(200).json({
            statusCode: 200,
            message: 'Product sales summary retrieved successfully',
            salesSummary: result.rows,
        });
    } catch (error) {
        console.error('Error retrieving sales summary:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to retrieve sales summary',
            error: error.message,
        });
    }
});

app.post('/sales/customer-monthly', verifyToken(['vendor', 'employee', 'customer']), async (req, res) => {
    const { vendorId, customerId, month, year, productId } = req.body;

    try {
        let queryText = `
            SELECT 
                s.id AS sale_id,
                s.vendor_id,
                s.customer_id,
                c.name AS customer_name,
                c.mobile AS customer_mobile,
                s.product_id,
                p.name AS product_name,
                p.unit AS product_unit,
                s.quantity,
                s.price_per_unit,
                s.total_amount,
                s.sale_date,
                s.invoice_generated,
                s.created_at,
                s.created_by,
                SUM(s.total_amount) OVER () AS total_monthly_expenses
            FROM 
                sales s
            JOIN 
                customers c ON s.customer_id = c.id
            JOIN 
                products p ON s.product_id = p.id
            WHERE 
                s.customer_id = $1 
                AND s.vendor_id = $2
                AND EXTRACT(MONTH FROM s.sale_date) = $3
                AND EXTRACT(YEAR FROM s.sale_date) = $4
        `;

        let queryValues = [customerId, vendorId, month, year];

        // 🛠️ Agar productId send hui hai toh uska bhi filter laga do
        if (productId) {
            queryText += ` AND s.product_id = $5`;
            queryValues.push(productId);
        }

        queryText += ` ORDER BY s.sale_date DESC`;

        const result = await pool.query({ text: queryText, values: queryValues });

        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'No sales data found for this customer',
            });
        }

        // **Format the date before sending the response**
        const salesData = result.rows.map((sale) => ({
            ...sale,
            formatted_date: new Intl.DateTimeFormat('en-US', {
                day: '2-digit',
                month: 'short',
                year: 'numeric',
                // timeZone: 'UTC',
            }).format(new Date(sale.sale_date)), // Format date to "13 Feb, 2024"
        }));

        const totalMonthlyExpenses = parseFloat(salesData[0].total_monthly_expenses) || 0;

        // **Fetch Grand Total for the Whole Month (All Products)**
        const totalQuery = `
            SELECT SUM(total_amount) AS grand_total FROM sales
            WHERE customer_id = $1
            AND vendor_id = $2
            AND EXTRACT(MONTH FROM sale_date) = $3
            AND EXTRACT(YEAR FROM sale_date) = $4
        `;
        const totalResult = await pool.query({ text: totalQuery, values: [customerId, vendorId, month, year] });
        const grandTotalMonthlyExpense = parseFloat(totalResult.rows[0].grand_total) || 0;

        res.status(200).json({
            statusCode: 200,
            message: 'Sales data retrieved successfully',
            totalMonthlyExpenses, // 🔹 Current product's total expense
            grandTotalMonthlyExpense, // 🔥 Whole month's total expense for all products
            sales: salesData, // 📋 Return sales data with customer and product details
        });
    } catch (error) {
        console.error('Error retrieving sales data:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to retrieve sales data',
            error: error.message,
        });
    }
});


//active customer count api for vendor
app.get('/customers/count', verifyToken(['vendor']), async (req, res) => {
    const vendorId = req.user.id; // Extract vendorId from the token

    try {
        const result = await pool.query({
            text: "SELECT COUNT(*) AS customer_count FROM customers WHERE vendor_id = $1 AND status = 'active'",
            values: [vendorId],
        });

        const customerCount = result.rows[0].customer_count;

        res.status(200).json({
            statusCode: 200,
            message: "success",
            data: {
                vendorId: vendorId,
                customerCount: parseInt(customerCount, 10) // Ensure the count is returned as an integer
            }
        });
    } catch (err) {
        console.error('Error fetching customer count:', err);
        res.status(500).json({
            statusCode: 500,
            message: 'Internal server error',
            error: err.message
        });
    }
});

//yesterday sales amount vendor
app.get('/sales/yesterday', verifyToken(['vendor']), async (req, res) => {
    const vendorId = req.user.id; // Extract vendorId from the token

    try {
        const result = await pool.query({
            text: `
                SELECT COALESCE(SUM(total_amount), 0) AS total_sales
                FROM sales
                WHERE vendor_id = $1
                AND DATE(sale_date) = CURRENT_DATE - INTERVAL '1 day'
            `,
            values: [vendorId],
        });

        const totalSales = result.rows[0].total_sales;

        res.status(200).json({
            statusCode: 200,
            message: "success",
            data: {
                vendorId: vendorId,
                totalSales: parseFloat(totalSales) // Ensure the sales amount is returned as a float
            }
        });
    } catch (err) {
        console.error('Error fetching total sales for yesterday:', err);
        res.status(500).json({
            statusCode: 500,
            message: 'Internal server error',
            error: err.message
        });
    }
});

//yesterday highest sale product
app.get('/sales/highest-product', verifyToken(['vendor']), async (req, res) => {
    const vendorId = req.user.id;

    try {

        const result = await pool.query({
            text: `
                SELECT 
                    p.id AS product_id,
                    p.name AS product_name,
                    SUM(s.quantity) AS total_quantity_sold
                FROM sales s
                INNER JOIN products p ON s.product_id = p.id
                WHERE s.vendor_id = $1
                AND DATE(s.sale_date) = CURRENT_DATE - INTERVAL '1 day'
                GROUP BY p.id, p.name
                ORDER BY total_quantity_sold DESC
                LIMIT 1
            `,
            values: [vendorId],
        });

        if (result.rows.length === 0) {
            return res.status(200).json({
                statusCode: 200,
                message: "No sales found for yesterday",
                data: null
            });
        }


        const highestSaleProduct = result.rows[0];

        res.status(200).json({
            statusCode: 200,
            message: "success",
            data: {
                productId: highestSaleProduct.product_id,
                product_name: highestSaleProduct.product_name,
                totalQuantitySold: parseFloat(highestSaleProduct.total_quantity_sold)
            }
        })
    } catch (err) {
        console.error('Error fetching highest sold product for yesterday:', err);
        res.status(500).json({
            statusCode: 500,
            message: 'Internal server error',
            error: err.message
        });
    }
})

//Total Active Products API
app.get('/active-products/count', verifyToken(['vendor']), async (req, res) => {
    const vendorId = req.user.id; // Extract vendorId from the token

    try {
        const result = await pool.query({
            text: "SELECT COUNT(*) AS active_product_count FROM products WHERE vendor_id = $1 AND status = 'active'",
            values: [vendorId],
        });

        const customerCount = result.rows[0].active_product_count;

        res.status(200).json({
            statusCode: 200,
            message: "success",
            data: {
                vendorId: vendorId,
                active_product_count: parseInt(customerCount, 10) // Ensure the count is returned as an integer
            }
        });
    } catch (err) {
        console.error('Error fetching products count:', err);
        res.status(500).json({
            statusCode: 500,
            message: 'Internal server error',
            error: err.message
        });
    }
});

// Vendor Registration Api
app.post('/register/vendor', async (req, res) => {
    const { name, email, mobile, address, business_name, gst_number } = req.body;

    if (!name || !mobile || !business_name) {
        return res.status(400).json({
            statusCode: 400,
            message: 'Name, email, mobile and business name are required fields.'
        });
    }

    try {
        // Check if email or mobile already exists
        const existingVendor = await pool.query(
            'SELECT * FROM vendors WHERE email = $1 OR mobile =$2',
            [email, mobile]
        );

        if (existingVendor.rows.length > 0) {
            return res.status(409).json({
                statusCode: 409,
                message: 'It looks like you already have an account with this email and mobile number. Please log in.'
            })
        }

        // Insert the new vendor into the database
        const result = await pool.query(
            `
            INSERT INTO vendors(name, email, mobile, address, business_name, gst_number)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, name, email, mobile, address, business_name, gst_number
            `,
            [name, email, mobile, address || null, business_name || null, gst_number || null]
        )

        const newVendor = result.rows[0];

        const createdBy = newVendor.id;

        // Update the created_by field for the vendor
        await pool.query(
            `
            UPDATE vendors
            SET created_by = $1
            WHERE id = $2
            `,
            [createdBy, createdBy]
        );


        // Create JWT token
        const payload = {
            id: result.id,
            mobile: result.mobile,
            name: result.name,
            userType: 'vendor'
        };

        const secretKey = process.env.JWT_SECRET || 'ABCD';
        const token = jwt.sign(payload, secretKey, { expiresIn: '1d' });

        return res.status(201).json({
            statusCode: 201,
            message: 'Vendor registered successfully.',
            data: newVendor,
            token
        })
    } catch (err) {
        res.status(500).json({
            statusCode: 500,
            message: 'Internal server error',
            error: err.message
        })
    }
})

//api to update sales for vendor
app.put('/sales/:sale_id', verifyToken(['vendor', 'employee']), async (req, res) => {
    const { sale_id } = req.params;
    const { quantity, price_per_unit, sale_date } = req.body;
    const updated_by = req.user.id; // Jisne update kiya
    let vendor_id;

    try {
        // Pehle sale ki vendor_id nikal lo
        const saleResult = await pool.query({
            text: `SELECT vendor_id FROM sales WHERE id = $1`,
            values: [sale_id],
        });

        if (saleResult.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'Sale not found',
            });
        }

        // Vendor ID assign karo (jo bhi sale ka owner hai)
        vendor_id = saleResult.rows[0].vendor_id;

        const total_amount = quantity * price_per_unit;

        // Ab update query chalao, lekin updated_by me vendor_id store karo
        const result = await pool.query({
            text: `
                UPDATE sales 
                SET 
                    quantity = $1,
                    price_per_unit = $2,
                    total_amount = $3,
                    sale_date = $4,
                    updated_by = $5, -- Yeh vendor_id hamesha hoga
                    updated_at = NOW()
                WHERE 
                    id = $6
                RETURNING id, quantity, price_per_unit, total_amount, sale_date, updated_by, updated_at;
            `,
            values: [quantity, price_per_unit, total_amount, sale_date, vendor_id, sale_id], // updated_by = vendor_id
        });

        res.status(200).json({
            statusCode: 200,
            message: 'Sales data updated successfully',
            sales: result.rows[0],
        });
    } catch (error) {
        console.error('Error updating sales data:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to update sales data',
            error: error.message,
        });
    }
});

//api to delete sales for vendor
app.delete('/sales/:sale_id', verifyToken(['vendor', 'employee']), async (req, res) => {
    const { sale_id } = req.params;
    // const vendor_id = req.user.id; // Extract vendor_id from token
    let vendor_id;

    try {
        // Pehle sale ki vendor_id nikal lo
        const saleResult = await pool.query({
            text: `SELECT vendor_id FROM sales WHERE id = $1`,
            values: [sale_id],
        });

        if (saleResult.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'Sale not found',
            });
        }

        // Vendor ID assign karo (jo bhi sale ka owner hai)
        vendor_id = saleResult.rows[0].vendor_id;

        const result = await pool.query({
            text: `
                DELETE FROM sales
                WHERE 
                    id = $1 AND vendor_id = $2
                RETURNING id, product_id, quantity, total_amount;
            `,
            values: [sale_id, vendor_id],
        });

        if (result.rows.length === 0) {
            return res.status(404).json({
                statusCode: 404,
                message: 'Sale not found or unauthorized',
            });
        }

        res.status(200).json({
            statusCode: 200,
            message: 'Sales data deleted successfully',
            data: result.rows[0], // Return updated data
        });
    } catch (error) {
        console.error('Error deleting sales data:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to delete sales data',
            error: error.message,
        });
    }
});

//get vendor details for payment (for customer)
app.post('/customer/qr', verifyToken(['customer']), async (req, res) => {
    const { vendorId } = req.body;

    // Validate vendorId
    if (!vendorId) {
        return res.status(400).json({ message: 'Vendor ID is required' });
    }

    try {

        // Query the function directly to get vendor details by ID
        const result = await pool.query(`
            SELECT id, name, business_name, mobile, email, business_image, qr_code_image FROM vendors 
            WHERE id = $1`
            , [vendorId]);

        // Check if result exists
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Vendor not found' });
        }

        // Return the JSON result with vendor details
        res.json({ statusCode: 200, message: "success", data: result.rows[0] });
    } catch (err) {
        console.error('Query error:', err.stack);
        res.status(500).send({ message: 'Internal server error' });
    }
});

//invoice generate
app.post('/generate-invoice', verifyToken(['vendor']), async (req, res) => {
    const { customer_id, month, year } = req.body;

    try {
        // Step 1: Define Start & End Dates
        const start_date = `${year}-${month.toString().padStart(2, '0')}-01`;
        const end_date = `${year}-${month.toString().padStart(2, '0')}-${new Date(year, month, 0).getDate()}`; // Last date of the month
        // const start_date = `${year}-${month.toString().padStart(2, '0')}-01`;
        // const current_date = new Date();
        // const end_date = `${year}-${month.toString().padStart(2, '0')}-${current_date.getDate()}`;

        // Step 2: Get all sales for the customer within the month
        const salesResult = await pool.query(
            "SELECT id, total_amount, sale_date FROM sales WHERE customer_id = $1 AND sale_date BETWEEN $2 AND $3",
            [customer_id, start_date, end_date]
        );

        if (salesResult.rows.length === 0) {
            return res.status(404).json({ message: "No sales found for this customer in the selected period." });
        }

        // Step 3: Find sales that are NOT present in any invoice yet
        const saleIds = salesResult.rows.map(sale => sale.id);
        const existingInvoices = await pool.query(
            "SELECT sale_id FROM invoice_details WHERE sale_id = ANY($1)",
            [saleIds]
        );

        const existingSaleIds = existingInvoices.rows.map(row => row.sale_id);
        const newSales = salesResult.rows.filter(sale => !existingSaleIds.includes(sale.id));

        if (newSales.length === 0) {
            return res.status(200).json({ message: "Your invoice is already generated for all sales in this period." });
        }

        // Step 4: Create a new invoice for the remaining sales
        const total_amount = newSales.reduce((sum, sale) => sum + parseFloat(sale.total_amount), 0);
        const newInvoice = await pool.query(
            "INSERT INTO invoice (start_date, end_date, total_amount, status, customer_id) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            [start_date, end_date, total_amount, 'pending', customer_id]
        );
        const invoice_id = newInvoice.rows[0].id;

        // Step 5: Insert new sales into invoice_details
        const insertQueries = newSales.map(sale =>
            pool.query(
                "INSERT INTO invoice_details (invoice_id, sale_id, paid_amount, amount) VALUES ($1, $2, $3, $4)",
                [invoice_id, sale.id, 0, sale.total_amount]
            )
        );

        await Promise.all(insertQueries);

        // **Step 6: Update sales table to set invoice_generated = true**
        await pool.query(
            "UPDATE sales SET invoice_generated = TRUE WHERE id = ANY($1)",
            [newSales.map(sale=>sale.id)]
        );

        res.status(201).json({ message: "Your invoice has been generated successfully.", invoice_id });

    } catch (err) {
        console.error('Query error:', err.stack);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// View All Invoices for a Customer
app.post('/view-invoice', verifyToken(['vendor']), async (req, res) => {
    const { customer_id } = req.body;

    try {
        if (!customer_id) {
            return res.status(400).json({ message: "Customer ID is required" });
        }

        const result = await pool.query(
            `SELECT id, total_amount, status, 
                    TO_CHAR(start_date, 'Month YYYY') AS month 
             FROM invoice 
             WHERE customer_id = $1 
             ORDER BY end_date DESC
            `, // Fetch all invoices, sorted by latest
            // ORDER BY id ASC
            [customer_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "No invoices found" });
        }

        res.json({ statusCode: 200, message: "Success", data: result.rows });

    } catch (err) {
        console.error('Query error:', err.stack);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// View Invoice Details
app.post('/view-invoice-detail', verifyToken(['vendor']), async (req, res) => {
    const { customer_id, invoice_id } = req.body;
    if (!invoice_id || !customer_id) {
        return res.status(400).json({ error: "invoice_id and customer_id are required" });
    }

    try {
        const query = `
            SELECT 
                i.id AS invoice_id,  
                i.total_amount,
                (i.total_amount - COALESCE(SUM(id.paid_amount), 0)) AS due_amount,
                COALESCE(SUM(id.paid_amount), 0) AS total_paid_amount,
                TO_CHAR(i.end_date, 'Mon DD, YYYY') AS end_date,
                JSON_AGG(
                    JSON_BUILD_OBJECT(
                        'product_name', p.name,
                        'sale_id', s.id,
                        'amount', s.total_amount,
                        'start_date', start_date,
                        'end_date', end_date,
                        'sale_date',TO_CHAR(s.sale_date, 'Mon DD, YYYY'),
                        'created_at', id.created_at
                    )
                ) AS sale_details
            FROM invoice i
            LEFT JOIN invoice_details id ON i.id = id.invoice_id  
            LEFT JOIN sales s ON id.sale_id = s.id  
            LEFT JOIN products p ON s.product_id = p.id  
            WHERE i.id = $1 AND i.customer_id = $2
            GROUP BY i.id, i.total_amount;
        `;

        const result = await pool.query(query, [invoice_id, customer_id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "No sales details found" });
        }

        res.json({ statusCode: 200, message: "success", data: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

//Make Payment API
app.post('/api/make-payment', verifyToken(['vendor']), async (req, res) => {
    const { invoice_id, customer_id, amount, payment_mode, notes, advancePayment } = req.body;

    if (!invoice_id || !customer_id || !amount || !payment_mode) {
        return res.status(400).json({ error: "invoice_id, customer_id, amount, and payment_mode are required" });
    }

    const client = await pool.connect(); // **Transaction ke liye client le rahe hain**

    try {
        await client.query('BEGIN'); // **Transaction Start**

        // **1. Get Total Due Amount for Invoice**
        const invoiceTotalQuery = `SELECT total_amount FROM invoice WHERE id = $1`;
        const invoiceTotalResult = await client.query(invoiceTotalQuery, [invoice_id]);

        if (invoiceTotalResult.rowCount === 0) {
            throw new Error("Invoice not found");
        }

        const totalAmount = parseFloat(invoiceTotalResult.rows[0].total_amount);

        // **2. Get Total Paid Amount**
        const totalPaidQuery = `SELECT COALESCE(SUM(paid_amount), 0) AS total_paid FROM invoice_details WHERE invoice_id = $1`;
        const totalPaidResult = await client.query(totalPaidQuery, [invoice_id]);
        const totalPaid = parseFloat(totalPaidResult.rows[0].total_paid);

        // **3. Calculate Remaining Due Amount**
        const remainingDue = totalAmount - totalPaid;

        // **Reject Extra Payment or Already Paid Invoice**
        if (remainingDue == 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({
                message: "Invoice already paid. No further payment is required.",
                remaining_due: remainingDue
            });
        }

        // **4. Reject Extra Payment**
        if (amount > remainingDue) {
            await client.query('ROLLBACK'); // **Transaction rollback**
            return res.status(400).json({ 
                message: "Payment exceeds due amount. Please enter a valid amount.",
                remaining_due: remainingDue
            });
        }

        if (advancePayment) {
            // **Advance Payment Case**
            const advancePaymentQuery = `
                UPDATE advance_payments
                SET advance_amount = advance_amount - $1, updated_at = NOW()
                WHERE customer_id = $2 AND advance_amount >= $1
                RETURNING id, advance_amount
            `;

            const advancePaymentResult = await client.query(advancePaymentQuery, [amount, customer_id]);

            // Debugging Log
            console.log("Advance Payment Query Result:", advancePaymentResult.rows);

            // Check if update was successful
            if (advancePaymentResult.rowCount === 0) {
                await client.query('ROLLBACK');
                return res.status(400).json({ message: "Insufficient advance balance" });
            }
        }

        // **5. Insert Payment (Even for Advance Payment)**
        const paymentQuery = `
            INSERT INTO payments (invoice_id, customer_id, amount, payment_mode, notes, payment_date, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
            RETURNING id
        `;
        const paymentResult = await client.query(paymentQuery, [invoice_id, customer_id, amount, payment_mode, notes || null]);

        let remainingAmount = parseFloat(amount);

        // **6. Fetch Invoice Details**
        const invoiceDetailsQuery = `
            SELECT id, amount, COALESCE(paid_amount, 0) AS paid_amount
            FROM invoice_details
            WHERE invoice_id = $1
            ORDER BY id ASC
        `;
        const invoiceDetailsResult = await client.query(invoiceDetailsQuery, [invoice_id]);

        for (const row of invoiceDetailsResult.rows) {
            if (remainingAmount <= 0) break;

            const dueForRow = row.amount - row.paid_amount;
            if (dueForRow <= 0) continue;

            let amountToApply = Math.min(remainingAmount, dueForRow);

            // **7. Update Paid Amount**
            const updateInvoiceDetailQuery = `
                UPDATE invoice_details
                SET paid_amount = paid_amount + $1
                WHERE id = $2
            `;
            await client.query(updateInvoiceDetailQuery, [amountToApply, row.id]);

            remainingAmount -= amountToApply;
        }

        // **8. Calculate Total Paid Again**
        const updatedTotalPaidQuery = `SELECT COALESCE(SUM(paid_amount), 0) AS total_paid FROM invoice_details WHERE invoice_id = $1`;
        const updatedTotalPaidResult = await client.query(updatedTotalPaidQuery, [invoice_id]);
        const updatedTotalPaid = parseFloat(updatedTotalPaidResult.rows[0].total_paid);

        // **9. Determine Invoice Status**
        let newStatus = 'pending';
        if (updatedTotalPaid >= totalAmount) {
            newStatus = 'completed';
        } else if (updatedTotalPaid > 0) {
            newStatus = 'partial';
        }

        // **10. Update Invoice Status**
        const updateInvoiceQuery = `UPDATE invoice SET status = $1 WHERE id = $2`;
        await client.query(updateInvoiceQuery, [newStatus, invoice_id]);

        await client.query('COMMIT'); // **Transaction Commit**

        res.json({
            success: true,
            message: "Payment processed and invoice updated successfully",
            payment_id: paymentResult.rows[0].id
        });

    } catch (err) {
        await client.query('ROLLBACK'); // **Agar koi bhi error aaya to poora rollback**
        console.error("Error processing payment:", err);
        res.status(500).json({ error: "Internal server error" });
    } finally {
        client.release(); // **Client connection release karna important hai**
    }
});


// Get Advance Payment
app.get('/api/advance-payment/:customer_id', verifyToken(['vendor']), async (req,res)=>{
    const { customer_id } = req.params;

    if(!customer_id){
        return res.status(400).json({message: "customer id are required"});
    }

    try{
        const query = `select * from advance_payments WHERE customer_id = $1`

        const result = await pool.query(query, [customer_id]);

        if(result.rowCount === 0){
            return res.status(400).json({message:"Advance payment record not found"});
        }

        res.json({
            statusCode: 200,
            message: 'success',
            data: result.rows[0]
        });
    }catch(err){
        // console.error("Error adding advance payment:", err);
        res.json({ message: "Internal server error" });
    }
});

// Add Advance Payment
app.post('/api/advance-payment', verifyToken(['vendor']), async (req, res) => {
    const { customer_id, advance_amount } = req.body;

    if (!customer_id || !advance_amount || advance_amount <= 0) {
        return res.status(400).json({ message: "customer id and valid advance amount are required" });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN'); // **Transaction Start**

        // **1. Update or Insert into advance_payments**
        const advancePaymentQuery = `
            INSERT INTO advance_payments (customer_id, advance_amount, created_at) 
            VALUES ($1, $2, NOW())
            ON CONFLICT (customer_id) 
            DO UPDATE SET advance_amount = advance_payments.advance_amount + EXCLUDED.advance_amount, updated_at = NOW()
            RETURNING id, customer_id, advance_amount, created_at, updated_at;
        `;
        const advancePaymentResult = await client.query(advancePaymentQuery, [customer_id, advance_amount]);

        // **2. Insert into advance_payment_history**
        const historyQuery = `
            INSERT INTO advance_payment_history (customer_id, advance_amount, payment_date)
            VALUES ($1, $2, NOW());
        `;
        await client.query(historyQuery, [customer_id, advance_amount]);

        await client.query('COMMIT'); // **Transaction Commit**

        res.json({
            success: true,
            message: "Advance payment added successfully",
            data: advancePaymentResult.rows[0]
        });

    } catch (err) {
        await client.query('ROLLBACK'); // **Rollback in case of error**
        console.error("Error adding advance payment:", err);
        res.status(500).json({ message: "Internal server error" });
    } finally {
        client.release();
    }
});

// Edit Advance Payment
app.put('/api/update-advance-payment', verifyToken(['vendor']), async (req, res) => {
    const { advance_amount, customer_id } = req.body;

    if (!customer_id || !advance_amount || advance_amount <= 0) {
        return res.status(400).json({ message: 'Valid customer_id and advance_amount are required' });
    }

    const client = await pool.connect();

    try {
        await client.query('BEGIN'); // **Transaction Start**

        // **Update advance_payments Table**
        const updateQuery = `
            UPDATE advance_payments
            SET advance_amount = $1, updated_at = NOW()
            WHERE customer_id = $2
            RETURNING id, customer_id, advance_amount, created_at, updated_at;
        `;
        const updateResult = await client.query(updateQuery, [advance_amount, customer_id]);

        if (updateResult.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ statusCode: 404, message: "Advance payment record not found" });
        }

        // ** Insert Update Log into advance_payment_history Table**
        const historyQuery = `
            INSERT INTO advance_payment_history (customer_id, advance_amount, payment_date, updated_at)
            VALUES ($1, $2, NOW(), NOW());
        `;
        await client.query(historyQuery, [customer_id, advance_amount]);

        await client.query('COMMIT'); // **Transaction Commit**

        res.json({
            statusCode: 200,
            message: "Advance payment updated successfully",
            data: updateResult.rows[0]
        });

    } catch (err) {
        await client.query('ROLLBACK'); // **Rollback in case of error**
        console.error("Error updating advance payment:", err);
        res.status(500).json({ statusCode: 500, message: "Internal server error" });
    } finally {
        client.release();
    }
});

//Monthly Due API
app.post('/api/monthly-due', verifyToken(['vendor']), async (req, res) => {
    const { customer_id } = req.body;
    if (!customer_id) {
        return res.status(400).json({ error: "customer_id are required" });
    }

    try {
        const query = `
           SELECT 
                COALESCE(SUM(i.total_amount), 0) - COALESCE(SUM(id.paid_amount), 0) AS monthly_due,
                COALESCE(SUM(id.paid_amount), 0) AS total_paid_amount
            FROM invoice i
            LEFT JOIN (
                SELECT invoice_id, SUM(paid_amount) AS paid_amount
                FROM invoice_details
                GROUP BY invoice_id
            ) id ON i.id = id.invoice_id
            WHERE i.customer_id = $1;
                    `;

        const result = await pool.query(query, [customer_id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: "No sales details found" });
        }

        res.json({ statusCode: 200, message: "success", data: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal Server Error" });
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
