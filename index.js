const dotenv = require("dotenv").config();
const express = require("express");
const { Pool } = require('pg');
const jwt = require("jsonwebtoken")

const app = express();
app.use(express.json());

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
            message: 'Customer created successfully',
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
app.get('/vendors/:vendorId/customers',verifyToken(['vendor','employee']), async (req, res) => {
    // Implement logic to get all customers for a specific vendor
    try {
        const result = await pool.query({
            text: `SELECT * FROM customers WHERE vendor_id = $1 AND status='active'`,
            values: [req.params.vendorId],
        });

        res.status(200).json({
            statusCode: 200,
            message: 'success',
            data: result.rows,
        });
    } catch (error) {
        console.error('Error fetching customers:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Failed to fetch customers',
            error: error.message,
        });
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
    const { name, email, mobile, address } = req.body;

    try {
        const result = await pool.query({
            text: 'SELECT * FROM update_customer($1, $2, $3, $4, $5, $6)',
            values: [customerId, name, email, mobile, address, updated_by],
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
            customer: result.rows[0],
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
    const { name, price_per_unit, unit } = req.body;

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
            text: 'SELECT * FROM update_product($1, $2, $3, $4, $5, $6)',
            values: [vendorId, productId, name, price_per_unit, unit, updated_by],
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
            product: result.rows[0],
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
app.post('/employees',verifyToken(['vendor']), async (req, res) => {
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
        text: 'SELECT * FROM employees WHERE vendor_id = $1',
        values: [vendorId],
      });
  
      if (result.rows.length === 0) {
        return res.status(200).json({ 
          statusCode: 200, 
          message: 'No employees found for this vendor', 
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
    const { name, email, mobile, role, address } = req.body;
    const updated_by = req.user.id;

    try {
        const result = await pool.query({
            text: 'SELECT * FROM update_employee($1, $2, $3, $4, $5, $6, $7)',
            values: [employeeId, name, email, mobile, role, address, updated_by],
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
    const { customer_id, product_id, quantity, price_per_unit, total_amount } = req.body;
    const vendor_id = req.user.id; // Extract vendor_id from token
    const created_by = req.user.id;       // Extract user ID from token
    console.log(req.user)
    try {
        const result = await pool.query({
            text: 'SELECT * FROM insert_sales($1, $2, $3, $4, $5, $6, $7)',
            values: [vendor_id, customer_id, product_id, quantity, price_per_unit, total_amount, created_by],
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
    const { vendor_id,customer_id, product_id, quantity, price_per_unit, total_amount } = req.body;
    const created_by = req.user.id;       // Extract user ID from token
    console.log(req.user)
    try {
        const result = await pool.query({
            text: 'SELECT * FROM insert_sales($1, $2, $3, $4, $5, $6, $7)',
            values: [vendor_id, customer_id, product_id, quantity, price_per_unit, total_amount, created_by],
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
app.post('/sales/customer', verifyToken(['vendor', 'employee','customer']), async (req, res) => {
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

        const salesData = result.rows;
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
                AND DATE(created_at) = CURRENT_DATE - INTERVAL '1 day'
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
app.get('/sales/highest-product',verifyToken(['vendor']),async(req,res)=>{
    const vendorId = req.user.id;

    try{

        const result = await pool.query({
            text: `
                SELECT 
                    p.id AS product_id,
                    p.name AS product_name,
                    SUM(s.quantity) AS total_quantity_sold
                FROM sales s
                INNER JOIN products p ON s.product_id = p.id
                WHERE s.vendor_id = $1
                AND DATE(s.created_at) = CURRENT_DATE - INTERVAL '1 day'
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
    }catch (err) {
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
app.post('/register/vendor', async(req,res)=>{
    const {name, email, mobile, address, business_name, gst_number} =  req.body;

    if(!name || !email || !mobile){
        return res.status(400).json({
            statusCode: 400,
            message: 'Name, email and mobile are required fields.'
        });
    }

    try{
        // Check if email or mobile already exists
        const existingVendor = await pool.query(
            'SELECT * FROM vendors WHERE email = $1 OR mobile =$2',
            [email,mobile]
        );

        if(existingVendor.rows.length > 0){
            return res.status(409).json({
                statusCode: 409,
                message: 'Email and mobile number are already registered'
            })
        }

        // Insert the new vendor into the database
        const result = await pool.query(
            `
            INSERT INTO vendors(name, email, mobile, address, business_name, gst_number)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, name, email, mobile, address, business_name, gst_number
            `,
            [ name, email, mobile, address || null, business_name ||null, gst_number || null]
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
    }catch(err){
        res.status(500).json({
            statusCode: 500,
            message: 'Internal server error',
            error: err.message
        })
    }
})



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
