require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const { parseISO, parse, format, isValid } = require('date-fns');

const app = express();
const UIPORT = process.env.UIPORT || 3000;
const APIPORT = process.env.PORT || 3001;

app.use(cors({
  origin: `http://localhost:${UIPORT}`, // Replace with your frontend URL
  credentials: true,
  exposedHeaders: ['X-New-Token']
}));

app.use(express.json());


const db = new sqlite3.Database(process.env.DATABASE_URL);
const SECRET_KEY = process.env.JWT_SECRET; // Replace with your secret key

// Create tables
  db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE, 
      password TEXT, 
      role Text)`);
  
    // Clients table
    db.run(`CREATE TABLE IF NOT EXISTS clients (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      address TEXT,
      phone TEXT,
      dob TEXT,
      remainingMinutes INTEGER DEFAULT 0,
      deleted BOOLEAN DEFAULT 0
    )`);
  
    // Products table
    db.run(`CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      price REAL,
      order_position INTEGER
    )`);
  
    // Transactions table
    db.run(`CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clientId INTEGER,
      totalAmount REAL,
      transactionDate DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(clientId) REFERENCES clients(id)
    )`);
  
    // Payment Methods table
    db.run(`CREATE TABLE IF NOT EXISTS paymentMethods (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE
    )`);
  
    // Payments table
    db.run(`CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      transactionId INTEGER,
      paymentMethodId INTEGER,
      amount REAL,
      paymentDate DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(transactionId) REFERENCES transactions(id),
      FOREIGN KEY(paymentMethodId) REFERENCES paymentMethods(id)
    )`);
  
    // Purchases table
    db.run(`CREATE TABLE IF NOT EXISTS purchases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clientId INTEGER,
      transactionId INTEGER,
      item TEXT,
      price REAL,
      purchaseDate DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(transactionId) REFERENCES transactions(id),
      FOREIGN KEY(clientId) REFERENCES clients(id)
    )`);
  
    // Minutes Used table
    db.run(`CREATE TABLE IF NOT EXISTS minutesUsed (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clientId INTEGER,
      minutes INTEGER DEFAULT 0,
      sunbedType TEXT,
      purchaseDate DATETIME DEFAULT CURRENT_TIMESTAMP,
      remainingMinutes INTEGER DEFAULT 0,
      FOREIGN KEY(clientId) REFERENCES clients(id)
    )`);
  
    // Insert default payment methods
    db.run(`INSERT OR IGNORE INTO paymentMethods (name) VALUES ('cash')`);
    db.run(`INSERT OR IGNORE INTO paymentMethods (name) VALUES ('card')`);
  
  // Insert initial products if they don't exist
  const sunbedMinutes = [
    { name: "3", price: 3.0 },
    { name: "6", price: 6.0 },
    { name: "9", price: 9.0 },
    { name: "12", price: 11.5 },
    { name: "15", price: 13.0 },
    { name: "18", price: 15.5 },
    { name: "21", price: 18.0 },
    { name: "30", price: 25.0 },
    { name: "60", price: 30.0 },
  ];

  sunbedMinutes.forEach(product => {
    db.run(
      `INSERT INTO products (name, price, order_position)
       SELECT ?, ?, (SELECT IFNULL(MAX(order_position), 0) + 1 FROM products)
       WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = ?)`,
      [product.name, product.price, product.name]
    );
  });

  const initialProducts = [
    { name: "Tanning Cream", price: 2.0 },
    { name: "Tanning Cream", price: 2.5 },
    { name: "Tanning Cream", price: 3.0 },
    { name: "Tanning Cream", price: 3.5 },
    { name: "Tanning Shot", price: 3.0 },
  ];

  initialProducts.forEach(product => {
    db.run(
      `INSERT INTO products (name, price, order_position)
       SELECT ?, ?, (SELECT IFNULL(MAX(order_position), 0) + 1 FROM products)
       WHERE NOT EXISTS (SELECT 1 FROM products WHERE name = ? AND price = ?)`,
      [product.name, product.price, product.name, product.price]
    );
  });

  db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, row) => {
    if (err) {
      return console.error(err.message);
    }

    if (!row) {
      // Admin user does not exist, create it
      const username = 'admin';
      const password = 'password';
      const role = 'admin';
      const salt = bcrypt.genSaltSync(10);
      const hashedPassword = bcrypt.hashSync(password, salt);

      db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role], (err) => {
        if (err) {
          return console.error(err.message);
        }
      });
    } else {
      console.log('Admin user already exists');
    }
  });
});

const authenticateTokenWithoutExtension = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ message: 'Access denied' });
  }

  try {
    const verified = jwt.verify(token, SECRET_KEY);
    req.user = verified;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Middleware to check authentication
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ message: 'Access denied' });
  }

  try {
    const verified = jwt.verify(token, SECRET_KEY);
    req.user = verified;
     // Extend token expiration by 1 hour
     const newToken = jwt.sign(
      { id: verified.id },
      SECRET_KEY,
      { expiresIn: '1h' }
    );
    
    // Set the new token in the response header
    res.setHeader('X-New-Token', newToken);
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

app.get('/user', authenticateToken, (req, res) => {
  const userId = req.user.id;

  db.get('SELECT role, username FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) {
      return res.status(500).json({ message: 'Error fetching user role' });
    }
    if (!row) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ role: row.role, username: row.username });
  });
});

//------------ register users ----------------//

// Register route
app.post('/user', authenticateToken, (req, res) => {
  const { username, password, role } = req.body;
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);

  db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role], function (err) {
    if (err) {
      return res.status(500).json({ message: 'User registration failed' });
    }
    res.status(201).json({ message: 'User registered successfully' });
  });
});

app.put('/user/:id', authenticateToken, (req, res) => {
  const { name, password } = req.body;
  const { id } = req.params;
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);

  db.run(`UPDATE users SET username = ?, password = ? WHERE id = ?`,
    [name, hashedPassword, id],
    function (err) {
      if (err) {
        res.status(400).json({ "error": err.message });
        return;
      }
      res.json({
        "message": "success",
        "changes": this.changes
      });
    });
});

app.delete('/user/:id', authenticateToken, (req, res) => {
  const userId = req.params.id;

  // First, check if the user exists and is not the admin
  db.get('SELECT username FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) {
      return res.status(500).json({ message: 'Error fetching user' });
    }
    if (!row) {
      return res.status(404).json({ message: 'User not found' });
    }
    if (row.username === 'admin') {
      return res.status(403).json({ message: 'Cannot delete admin user' });
    }

    // If all checks pass, proceed with deletion
    db.run('DELETE FROM users WHERE id = ?', [userId], function (err) {
      if (err) {
        return res.status(500).json({ message: 'Failed to delete user' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ message: 'User not found' });
      }
      res.json({ message: 'User deleted successfully' });
    });
  });
});

app.get('/users', authenticateToken, (req, res) => {
  db.all('SELECT id, username, role FROM users ORDER BY username', [], (err, rows) => {
    if (err) {
      res.status(400).json({ "error": err.message });
      return;
    }
    res.json(rows);
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Login failed' });
    }
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  });
});


// Get all clients
app.get('/clients', authenticateToken, (req, res) => {
  db.all('SELECT * FROM clients WHERE deleted = 0', [], (err, rows) => {
    if (err) {
      res.status(400).json({ "error": err.message });
      return;
    }
    res.json(rows);
  });
});

// Now, let's create the endpoint for deleting a client
app.delete('/client/:id', authenticateToken, (req, res) => {
  const clientId = req.params.id;

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    // Check if the client exists and is not already deleted
    db.get('SELECT name FROM clients WHERE id = ? AND deleted = 0', [clientId], (err, row) => {
      if (err) {
        db.run('ROLLBACK');
        return res.status(500).json({ message: 'Error fetching client' });
      }
      if (!row) {
        db.run('ROLLBACK');
        return res.status(404).json({ message: 'Client not found or already deleted' });
      }

      // Mark client as deleted
      db.run(`UPDATE clients SET 
                deleted = 1 
              WHERE id = ?`, 
        [clientId], 
        (err) => {
          if (err) {
            db.run('ROLLBACK');
            return res.status(500).json({ message: 'Failed to delete client' });
          }

          db.run('COMMIT', (err) => {
            if (err) {
              db.run('ROLLBACK');
              return res.status(500).json({ message: 'Failed to commit changes' });
            }
            res.json({ message: 'Client deleted successfully' });
          });
        }
      );
    });
  });
});

app.get('/products', authenticateToken, (req, res) => {
  db.all('SELECT * FROM products ORDER BY order_position', [], (err, rows) => {
    if (err) {
      res.status(400).json({ "error": err.message });
      return;
    }
    res.json(rows);
  });
});

// Add a new product
app.post('/products', authenticateToken, (req, res) => {
  const { name, price } = req.body;
  db.serialize(() => {
    db.get('SELECT MAX(order_position) as maxOrder FROM products', [], (err, row) => {
      if (err) {
        res.status(400).json({ "error": err.message });
        return;
      }
      const newOrder = (row.maxOrder || 0) + 1;
      db.run(`INSERT INTO products (name, price, order_position) VALUES (?, ?, ?)`,
        [name, price, newOrder],
        function (err) {
          if (err) {
            res.status(400).json({ "error": err.message });
            return;
          }
          res.json({
            "message": "success",
            "data": { id: this.lastID, order_position: newOrder }
          });
        });
    });
  });
});

app.put('/products/reorder', authenticateToken, (req, res) => {
  const { products } = req.body;

  if (!Array.isArray(products)) {
    res.status(400).json({ "error": "Invalid input. Expected an array of products." });
    return;
  }

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    products.forEach((product) => {
      db.run('UPDATE products SET order_position = ? WHERE id = ?', [product.order, product.id], (err) => {
        if (err) {
          console.error('Error updating product order:', err);
          db.run('ROLLBACK');
          res.status(500).json({ "error": "Failed to update product order" });
          return;
        }
      });
    });

    db.run('COMMIT', (err) => {
      if (err) {
        console.error('Error committing transaction:', err);
        db.run('ROLLBACK');
        res.status(500).json({ "error": "Failed to commit changes" });
        return;
      }
      res.json({ "message": "Product order updated successfully" });
    });
  });
});

// Delete a product
app.delete('/products/:id', authenticateToken, (req, res) => {
  const id = req.params.id;

  // First, check if the product exists and if its name is numeric
  db.get('SELECT name FROM products WHERE id = ?', [id], (err, row) => {
    if (err) {
      res.status(400).json({ "error": err.message });
      return;
    }
    if (!row) {
      res.status(404).json({ "error": "Product not found" });
      return;
    }

    // Check if the product name is a positive number
    if (!isNaN(row.name) && Number(row.name) > 0) {
      res.status(400).json({ "error": "Cannot delete products with numeric names" });
      return;
    }

    // If checks pass, proceed with deletion
    db.run('DELETE FROM products WHERE id = ?', id, function (err) {
      if (err) {
        res.status(400).json({ "error": err.message });
        return;
      }
      res.json({
        "message": "deleted",
        "changes": this.changes
      });
    });
  });
});

app.put('/products/:id', authenticateToken, (req, res) => {
  const { name, price } = req.body;
  const { id } = req.params;
  db.run(`UPDATE products SET name = ?, price = ? WHERE id = ?`,
    [name, price, id],
    function (err) {
      if (err) {
        res.status(400).json({ "error": err.message });
        return;
      }
      res.json({
        "message": "success",
        "changes": this.changes
      });
    });
});

// Add a new client
app.post('/addclient', authenticateToken, (req, res) => {
  const { name, address, phone, dob } = req.body;
  db.run(`INSERT INTO clients (name, address, phone, dob, remainingMinutes) VALUES (?, ?, ?, ?, 0)`,
    [name, address, phone, dob],
    function (err) {
      if (err) {
        res.status(400).json({ "error": err.message });
        return;
      }
      res.json({
        "message": "success",
        "data": { id: this.lastID }
      });
    });
});

app.get('/purchases', authenticateToken, (req, res) => {
  const { purchaseDate } = req.query;
  if (!purchaseDate) {
    return res.status(400).json({ "error": "purchaseDate is required" });
  }

  // Parse the input date and create start and end of day in ISO format
 // Try parsing as ISO first
 parsedDate = parseISO(purchaseDate);

 // If invalid, try parsing as DD/MM/YYYY
 if (!isValid(parsedDate)) {
   parsedDate = parse(purchaseDate, 'dd/MM/yyyy', new Date());
 }

 // If still invalid, return an error
 if (!isValid(parsedDate)) {
   return res.status(400).json({ "error": "Invalid date format. Use ISO 8601 or DD/MM/YYYY" });
 }
   const startDate = format(parsedDate, "yyyy-MM-dd'T'00:00:00.000'Z'");
  const endDate = format(parsedDate, "yyyy-MM-dd'T'23:59:59.999'Z'");

  // Fetch purchases and minutes used, along with the most recent activity
  const sql = `
    WITH combined_data AS (
      SELECT 
        c.id AS clientId,
        c.name,
        'purchase' AS type,
        p.item AS detail,
        p.price,
        p.purchaseDate AS activityDate
      FROM purchases p
      JOIN clients c ON p.clientId = c.id
      WHERE p.purchaseDate >= ? AND p.purchaseDate <= ?
      
      UNION ALL
      
      SELECT 
        c.id AS clientId,
        c.name,
        'minutes' AS type,
        m.minutes AS detail,
        0 AS price,
        m.purchaseDate AS activityDate
      FROM minutesUsed m
      JOIN clients c ON m.clientId = c.id
      WHERE m.purchaseDate >= ? AND m.purchaseDate <= ?
    )
    SELECT 
      clientId,
      name,
      MAX(activityDate) AS lastActivityDate,
      GROUP_CONCAT(CASE WHEN type = 'purchase' THEN detail ELSE NULL END) AS purchases,
      GROUP_CONCAT(CASE WHEN type = 'minutes' THEN detail ELSE NULL END) AS minutes,
      SUM(price) AS total
    FROM combined_data
    GROUP BY clientId, name
    ORDER BY lastActivityDate DESC
  `;

  db.all(sql, [startDate, endDate, startDate, endDate], (err, rows) => {
    if (err) {
      return res.status(400).json({ "error": err.message });
    }
    const result = rows.map(row => ({
      id: row.clientId,
      name: row.name,
      minutes: row.minutes ? row.minutes.split(',').map(Number) : [],
      purchases: row.purchases ? row.purchases.split(',') : [],
      total: row.total
    }));

    res.json(result);
  });
});

// Add purchase and update minutes if applicable
app.post('/purchases', authenticateToken, (req, res) => {
  const currentTime = new Date().toISOString();
  const { clientId, items, transaction } = req.body;

  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    // Insert into transactions table
    db.run(`INSERT INTO transactions (clientId, totalAmount, transactionDate) VALUES (?, ?, ?)`,
      [clientId, transaction.reduce((sum, t) => sum + t.amount, 0), currentTime],
      function(err) {
        if (err) {
          console.error("Error inserting transaction:", err);
          db.run('ROLLBACK');
          return res.status(400).json({ "error": err.message });
        }

        const transactionId = this.lastID;

        // Insert into payments table
        const paymentStmt = db.prepare(`INSERT INTO payments (transactionId, paymentMethodId, amount, paymentDate) VALUES (?, ?, ?, ?)`);
        
        transaction.forEach(t => {
          const paymentMethodId = t.transactionId; // Assuming 1 for cash, 2 for card
          paymentStmt.run([transactionId, paymentMethodId, t.amount, currentTime], (err) => {
            if (err) {
              console.error("Error inserting payment:", err);
              db.run('ROLLBACK');
              return res.status(400).json({ "error": err.message });
            }
          });
        });

        paymentStmt.finalize();

        // Insert into purchases table
        const purchaseStmt = db.prepare(`INSERT INTO purchases (clientId, item, price, purchaseDate, transactionId) VALUES (?, ?, ?, ?, ?)`);
        let minutesToAdd = 0;

        items.forEach(item => {
          purchaseStmt.run([clientId, item.name, item.price, currentTime, transactionId], (err) => {
            if (err) {
              console.error("Error inserting purchase:", err);
              db.run('ROLLBACK');
              return res.status(400).json({ "error": err.message });
            }
          });

          // If the item is "Minutes", add to minutesToAdd
          if (item.name.toLowerCase().includes("minutes")) {
            let parts = item.name.split(" ");
            if (parts.length > 0 && !isNaN(parts[0])) {
              minutesToAdd += parseInt(parts[0]);
            }
          }
        });

        purchaseStmt.finalize();

        // If minutes were purchased, update the client's remainingMinutes
        if (minutesToAdd > 0) {
          db.run(`UPDATE clients SET remainingMinutes = remainingMinutes + ? WHERE id = ?`,
            [minutesToAdd, clientId],
            (err) => {
              if (err) {
                console.error("Error updating remaining minutes:", err);
                db.run('ROLLBACK');
                return res.status(400).json({ "error": err.message });
              }
            }
          );
        }

        db.run('COMMIT', (err) => {
          if (err) {
            console.error("Error committing transaction:", err);
            db.run('ROLLBACK');
            return res.status(400).json({ "error": err.message });
          }
          res.json({
            "message": "success",
            "data": { itemsAdded: items.length, minutesAdded: minutesToAdd }
          });
        });
      }
    );
  });
});

// Update client
app.put('/client/:selectedClient', authenticateToken, (req, res) => {
  const { name, phone, address, dob } = req.body;
  const { selectedClient } = req.params;
  db.run(`UPDATE clients SET name = ?, phone = ?, address = ?, dob = ? WHERE id = ?`,
    [name, phone, address, dob, selectedClient],
    function (err) {
      if (err) {
        res.status(400).json({ "error": err.message });
        return;
      }
      res.json({
        "message": "success",
        "changes": this.changes
      });
    });
});


//------- client-history --------//
app.get('/customer-history', authenticateToken, (req, res) => {
  const sql = `
      SELECT 
      c.id, c.name, c.phone, c.address, c.remainingMinutes as clientRemainingMinutes,
      p.id as purchaseId, p.item, p.price, p.purchaseDate,
      m.id as minutesUsedId, m.minutes, m.purchaseDate as minutesUsedDate,
      m.remainingMinutes as minutesUsedRemainingMinutes
    FROM clients c
    LEFT JOIN purchases p ON c.id = p.clientId
    LEFT JOIN minutesUsed m ON c.id = m.clientId
    WHERE c.deleted = 0
    ORDER BY c.name, p.purchaseDate DESC, m.purchaseDate DESC
    `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      res.status(400).json({ "error": err.message });
      return;
    }

    // Process the rows to group by client
    const clientMap = new Map();
    rows.forEach(row => {
      if (!clientMap.has(row.id)) {
        clientMap.set(row.id, {
          id: row.id,
          name: row.name,
          phone: row.phone,
          address: row.address,
          remainingMinutes: row.clientRemainingMinutes,
          purchases: [],
          minutesUsed: []
        });
      }

      const client = clientMap.get(row.id);

      if (row.purchaseId) {
        client.purchases.push({
          id: row.purchaseId,
          item: row.item,
          price: row.price,
          purchaseDate: row.purchaseDate,
          minutes: parseInt(row.item.split(' ')[0]) // assuming item format is like "15 minutes"
        });
      }

      if (row.minutesUsedId) {
        if (row.item?.endsWith("minutes")) {
          client.minutesUsed.push({
            id: row.minutesUsedId,
            minutes: row.minutes,
            remainingMinutes: row.minutesUsedRemainingMinutes,
            date: row.minutesUsedDate
          });
        }
      }
    });

    // Merge purchases into minutesUsed
    clientMap.forEach(client => {
      client.purchases.forEach(purchase => {
        if (purchase.item?.endsWith("minutes")) {
          client.minutesUsed.push({
            id: `purchase-${purchase.id}`, // unique id for purchases
            minutes: `+${purchase.minutes}`,
            remainingMinutes: null, // or calculate if needed
            date: purchase.purchaseDate
          });
        }
      });

      // Sort minutesUsed array by date
      client.minutesUsed.sort((a, b) => new Date(b.date) - new Date(a.date));
    });

    res.json(Array.from(clientMap.values()));
  });
});


app.get('/customer-history/:clientId', authenticateToken, (req, res) => {
  const clientId = req.params.clientId;
  const sql = `
    SELECT 
      c.id, c.name, c.phone, c.address, c.remainingMinutes as clientRemainingMinutes,
      p.id as purchaseId, p.item, p.price, p.purchaseDate,
      m.id as minutesUsedId, m.minutes, m.purchaseDate as minutesUsedDate,
      m.remainingMinutes as minutesUsedRemainingMinutes
    FROM clients c
    LEFT JOIN purchases p ON c.id = p.clientId
    LEFT JOIN minutesUsed m ON c.id = m.clientId
    WHERE c.id = ?
    ORDER BY p.purchaseDate DESC, m.purchaseDate DESC
  `;

  db.all(sql, [clientId], (err, rows) => {
    if (err) {
      res.status(400).json({ "error": err.message });
      return;
    }

    if (rows.length === 0) {
      res.status(404).json({ "error": "Client not found" });
      return;
    }

    // Process the rows for the single client
    const client = {
      id: rows[0].id,
      name: rows[0].name,
      phone: rows[0].phone,
      address: rows[0].address,
      remainingMinutes: rows[0].clientRemainingMinutes,
      purchases: [],
      minutesUsed: []
    };

    rows.forEach(row => {
      if (row.purchaseId) {
        client.purchases.push({
          id: row.purchaseId,
          item: row.item,
          price: row.price,
          purchaseDate: row.purchaseDate,
          minutes: parseInt(row.item.split(' ')[0]) // assuming item format is like "15 minutes"
        });
      }

      if (row.minutesUsedId) {
        if (row.item?.endsWith("minutes")) {
          client.minutesUsed.push({
            id: row.minutesUsedId,
            minutes: row.minutes,
            remainingMinutes: row.minutesUsedRemainingMinutes,
            date: row.minutesUsedDate
          });
        }
      }
    });

    // Merge purchases into minutesUsed
    client.purchases.forEach(purchase => {
      if (purchase.item?.endsWith("minutes")) {
        client.minutesUsed.push({
          id: `purchase-${purchase.id}`, // unique id for purchases
          minutes: `+${purchase.minutes}`,
          remainingMinutes: null, // or calculate if needed
          date: purchase.purchaseDate
        });
      }
    });

    // Sort minutesUsed array by date
    client.minutesUsed.sort((a, b) => new Date(b.date) - new Date(a.date));

    res.json([client]); // Wrap the single client object in an array to maintain the same return format
  });
});

// Use minutes
app.post('/sunbed-session', authenticateToken, (req, res) => {
  const { clientId, minutes, sunbedType } = req.body;
  const currentTime = new Date();
  
  db.serialize(() => {
    db.run('BEGIN TRANSACTION');

    // First, update the client's remaining minutes
    db.run(`UPDATE clients SET remainingMinutes = remainingMinutes - ? WHERE id = ?`,
      [minutes, clientId],
      function (err) {
        if (err) {
          db.run('ROLLBACK');
          res.status(400).json({ "error": err.message });
          return;
        }

        // Fetch the updated remainingMinutes
        db.get(`SELECT remainingMinutes FROM clients WHERE id = ?`, [clientId], (err, row) => {
          if (err) {
            db.run('ROLLBACK');
            res.status(400).json({ "error": err.message });
            return;
          }

          const updatedRemainingMinutes = row.remainingMinutes;

          // Check for active and pending sessions of the same type
          db.all(`
            SELECT purchaseDate, minutes
            FROM minutesUsed
            WHERE sunbedType = ? AND datetime(purchaseDate, '+' || minutes || ' minutes') > datetime(?)
            ORDER BY purchaseDate ASC
          `, [sunbedType, currentTime.toISOString()], (err, sessions) => {
            if (err) {
              db.run('ROLLBACK');
              res.status(400).json({ "error": err.message });
              return;
            }

            let purchaseDate = currentTime;
            if (sessions.length > 0) {
              // Calculate the end time of the last session
              let lastSessionEnd = new Date(sessions[sessions.length - 1].purchaseDate);
              lastSessionEnd.setMinutes(lastSessionEnd.getMinutes() + sessions[sessions.length - 1].minutes + 2);
              
              // If the last session ends in the future, use its end time
              if (lastSessionEnd > currentTime) {
                purchaseDate = lastSessionEnd;
              }
            }

            // Insert the new session
            db.run(`INSERT INTO minutesUsed (clientId, minutes, sunbedType, purchaseDate, remainingMinutes) 
            VALUES (?, ?, ?, ?, ?)`,
              [clientId, minutes, sunbedType, purchaseDate.toISOString(), updatedRemainingMinutes],
              function (err) {
                if (err) {
                  db.run('ROLLBACK');
                  res.status(400).json({ "error": err.message });
                  return;
                }

                db.run('COMMIT', (err) => {
                  if (err) {
                    db.run('ROLLBACK');
                    res.status(400).json({ "error": err.message });
                    return;
                  }

                  res.json({
                    "message": "success",
                    "changes": this.changes,
                    "purchaseDate": purchaseDate.toISOString()
                  });
                });
              });
          });
        });
      });
  });
});

// Get current sunbed session status
app.get('/sunbed-timer/:type', authenticateTokenWithoutExtension, (req, res) => {
  const { type } = req.params;
  const currentTime = new Date();

  db.get(`SELECT * FROM minutesUsed 
          WHERE sunbedType = ? 
          AND datetime(purchaseDate, '+' || (minutes + 2) || ' minutes') > datetime(?)
          ORDER BY purchaseDate ASC LIMIT 1`, 
    [type, currentTime.toISOString()], 
    (err, currentSession) => {
      if (err) {
        res.status(400).json({ "error": err.message });
        return;
      }

      db.all(`SELECT clientId, minutes FROM minutesUsed 
              WHERE sunbedType = ? 
              AND datetime(purchaseDate, '+' || (minutes + 2) || ' minutes') > datetime(?)
              ORDER BY purchaseDate ASC`, 
        [type, currentTime.toISOString()], 
        (err, waitingClients) => {
          if (err) {
            res.status(400).json({ "error": err.message });
            return;
          }

          res.json({
            currentSession: currentSession ? {
              ...currentSession,
              remainingTime: Math.max(0, new Date(new Date(currentSession.purchaseDate).getTime() + (currentSession.minutes + 2) * 60000) - currentTime) / 1000
            } : null,
            waitingClients: waitingClients.slice(1) // Exclude the current session
          });
        });
    });
});

app.get('/transactions', authenticateToken, (req, res) => {
  const { date } = req.query;
  if (!date) {
    return res.status(400).json({ "error": "date is required" });
  }

  // Parse the input date and create start and end of day in ISO format
  let parsedDate = parseISO(date);

  // If invalid, try parsing as DD/MM/YYYY
  if (!isValid(parsedDate)) {
    parsedDate = parse(date, 'dd/MM/yyyy', new Date());
  }

  // If still invalid, return an error
  if (!isValid(parsedDate)) {
    return res.status(400).json({ "error": "Invalid date format. Use ISO 8601 or DD/MM/YYYY" });
  }
  const startDate = format(parsedDate, "yyyy-MM-dd'T'00:00:00.000'Z'");
  const endDate = format(parsedDate, "yyyy-MM-dd'T'23:59:59.999'Z'");

  const transactionsSql = `
    SELECT 
      t.id AS transactionId,
      c.id AS clientId,
      CASE WHEN c.deleted = 1 THEN c.name || ' (Removed)' ELSE c.name END AS clientName,
      t.totalAmount,
      t.transactionDate
    FROM transactions t
    JOIN clients c ON t.clientId = c.id
    WHERE t.transactionDate >= ? AND t.transactionDate <= ?
    ORDER BY t.transactionDate DESC
  `;

  const purchasesSql = `
    SELECT 
      p.transactionId,
      p.item || ' (£' || p.price || ')' AS purchaseItem
    FROM purchases p
    JOIN transactions t ON p.transactionId = t.id
    WHERE t.transactionDate >= ? AND t.transactionDate <= ?
  `;

  const paymentsSql = `
    SELECT 
      pay.transactionId,
      pm.name AS paymentMethod,
      pay.amount
    FROM payments pay
    JOIN paymentMethods pm ON pay.paymentMethodId = pm.id
    JOIN transactions t ON pay.transactionId = t.id
    WHERE t.transactionDate >= ? AND t.transactionDate <= ?
  `;

  const minutesSql = `
    SELECT 
      c.id AS clientId,
      CASE WHEN c.deleted = 1 THEN c.name || ' (Removed)' ELSE c.name END AS clientName,
      m.minutes,
      m.purchaseDate
    FROM minutesUsed m
    JOIN clients c ON m.clientId = c.id
    WHERE m.purchaseDate >= ? AND m.purchaseDate <= ?
  `;

  db.serialize(() => {
    db.all(transactionsSql, [startDate, endDate], (err, transactions) => {
      if (err) {
        return res.status(400).json({ "error": err.message });
      }

      db.all(purchasesSql, [startDate, endDate], (err, purchases) => {
        if (err) {
          return res.status(400).json({ "error": err.message });
        }

        db.all(paymentsSql, [startDate, endDate], (err, payments) => {
          if (err) {
            return res.status(400).json({ "error": err.message });
          }

          db.all(minutesSql, [startDate, endDate], (err, minutes) => {
            if (err) {
              return res.status(400).json({ "error": err.message });
            }

            let dailyCashTotal = 0;
            let dailyCardTotal = 0;

            // Create fake transactions for minutes usage
            const minutesTransactions = minutes.map(m => ({
              transactionId: `minutes-${m.clientId}-${m.purchaseDate}`,
              clientId: m.clientId,
              clientName: m.clientName,
              totalAmount: 0,
              transactionDate: m.purchaseDate,
              isMinutesUsage: true,
              minutes: m.minutes
            }));

            const allTransactions = [...transactions, ...minutesTransactions];

            const result = allTransactions.map(transaction => {
              const transactionPurchases = transaction.isMinutesUsage
                ? [`Minutes Used: ${transaction.minutes}`]
                : purchases
                    .filter(p => p.transactionId === transaction.transactionId)
                    .map(p => p.purchaseItem);

              const transactionPayments = transaction.isMinutesUsage
                ? {}
                : payments
                    .filter(p => p.transactionId === transaction.transactionId)
                    .reduce((acc, payment) => {
                      if (!acc[payment.paymentMethod.toLowerCase()]) {
                        acc[payment.paymentMethod.toLowerCase()] = 0;
                      }
                      acc[payment.paymentMethod.toLowerCase()] += payment.amount;
                      if (payment.paymentMethod.toLowerCase() === 'cash') {
                        dailyCashTotal += payment.amount;
                      } else if (payment.paymentMethod.toLowerCase() === 'card') {
                        dailyCardTotal += payment.amount;
                      }
                      return acc;
                    }, {});

              return {
                id: transaction.transactionId,
                clientName: transaction.clientName,
                totalAmount: transaction.totalAmount,
                date: transaction.transactionDate,
                purchaseItems: transactionPurchases,
                payments: transactionPayments,
                isMinutesUsage: transaction.isMinutesUsage || false
              };
            });

            res.json({
              transactions: result,
              dailyTotals: {
                cash: dailyCashTotal,
                card: dailyCardTotal,
                total: dailyCashTotal + dailyCardTotal
              }
            });
          });
        });
      });
    });
  });
});

app.listen(APIPORT, () => {
  console.log(`Server running on port ${APIPORT}`);
});