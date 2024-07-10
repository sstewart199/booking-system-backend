# Sunbed User Management Backend

This repository contains the backend for a sunbed user management system. It provides API endpoints to interact with the frontend user interface located at [https://github.com/sstewart199/booking-system](https://github.com/sstewart199/booking-system).

## Technologies Used

- Node.js
- Express
- SQLite3

## Features

The backend provides API endpoints for:

- Client management (add and update clients)
- Purchase management (items and sunbed minutes)
- Sunbed minute usage tracking
- Client minute tracking
- Client purchase history
- Daily purchase history and totals
- User/staff management

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/sstewart199/booking-system-backend.git
   cd booking-system-backend
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Set up the environment:
   - Create a `.env` file in the root directory
   - Add the following to the `.env` file:
     ```
     DB_NAME=sunbed.db
     TOKEN=your_random_token_here
     ```
   Replace `your_random_token_here` with a secure random string.

4. Start the server:
   ```
   node server.js
   ```
   The database will be created automatically if it doesn't exist.

## Usage

[Add information about how to use the API, including any authentication requirements and example requests/responses]

## API Endpoints

[List and describe your main API endpoints here. For example:]

- `POST /api/clients`: Add a new client
- `PUT /api/clients/:id`: Update client information
- `POST /api/purchases`: Record a new purchase
- `POST /api/sunbed/use`: Record sunbed minute usage
- `GET /api/clients/:id/minutes`: Get client's remaining minutes
- `GET /api/clients/:id/history`: Get client's purchase history
- `GET /api/daily-totals`: Get daily purchase totals

## Contributing

[Add information about how others can contribute to this project, if applicable]

## License

[Add your license information here]

## Contact

For any inquiries, please contact:

Email: sstewart199@gmail.com

GitHub: [https://github.com/sstewart199](https://github.com/sstewart199)# booking-system-backend
