# Go Boundless

The Python backend is a robust REST API built using **Flask** that powers our eSIM shop. It connects our frontend with various services including the **Dent eSIM provider** to manage and provision mobile data packages in real time. It also integrates with Mailgun for email sending, Stripe and Now Payments for secure payment processing, and implements JWT for user authentication.



## Features

- **Dent Integration**  
  Communicates with the Dent eSIM provider’s API to handle mobile data packages and ensure users have real-time access to their eSIM services.

- **User Management**  
  Offers endpoints for user registration, login, account management, and role-based access (e.g., superadmin).

- **Payment Processing**  
  Supports fiat and cryptocurrency payments via Stripe and Now Payments. 

- **Email Notifications**  
  Uses Mailgun to send emails for account verification, password resets, and support responses.

- **Secure JWT Authentication**  
  Implements robust JWT-based auth, complete with token revocation and role-based claims.

- **API Documentation**  
  Provides auto-generated Swagger (OpenAPI) documentation for easy testing and integration.
## Environment Variables

Create a `.env` file in the root directory of the project and define the following variables:

```bash
DENT_CLIENT_ID=
DENT_CLIENT_SECRET=
SUPERADMIN_EMAIL=
SUPERADMIN_PASSWORD=
MAILGUN_API_KEY=
EMAIL_FROM=
JWT_SECRET_KEY=
STRIPE_PRIVATE_KEY=
SUPPORT_TEAM_EMAILS=
STRIPE_ENDPOINT_SECRET=
DATABASE_USERNAME=
DATABASE_PASSWORD=
DATABASE_HOST=
DATABASE_PORT=
DATABASE_NAME=
NOW_PAYMENT_API_KEY=
NOW_PAYMENT_API_LINK=
DENT_LINK=
```

Create a `.flaskenv` file in the root directory of the project and define the following variables: 

```bash
FLASK_APP=main.py
FLASK_DEBUG=1
```

## Installation

Clone the Repo:

```bash
  git clone https://github.com/liquify-validation/go-boundless-backend.git
```

### Optional 

Create a virtual environment :


```bash
  python -m venv venv
  source venv/bin/activate  # On Windows, use: venv\Scripts\activate

```

Install Dependencies

```bash
  pip install -r requirements.txt

```

## Usage


Local Development
After configuring your .env file and installing dependencies, run:

```bash
  flask run --host=0.0.0.0

```

This starts the backend at http://localhost:5000.

Docker
A Dockerfile is included for containerized deployments:

```bash
  # Build the Docker image
docker build -t go-boundless-backend .

# Run the container (ensure you have your .env file in place)
docker run -p 5000:5000 --env-file .env go-boundless-backend

```
The service will be accessible at http://localhost:5000.

Database Migrations
This project uses Flask-Migrate to manage database schema changes.

Initialize Migrations (if not already done):

```bash
  flask db init
```

Generate a New Migration Script:

```bash
  flask db migrate -m "Your migration message"
```

Apply Migrations:


```bash
  flask db upgrade
```
## Deployment

When you're ready to deploy:

Ensure your production environment variables in .env (or your orchestrator’s environment configuration) are correct.

Build the Docker image and push it to your chosen registry, or deploy the container as part of your preferred hosting/platform.

Run database migrations on your production environment if needed.
## Contributing

Contributions are always welcome!

Fork the repo and create a new branch for your feature or bug fix.

Commit changes with clear messages.

Open a Pull Request describing your changes.

Please follow any coding style or lint guidelines and ensure your code builds successfully before submitting.
## License

[MIT](https://choosealicense.com/licenses/mit/)


## Additional Notes

You can find the react frontend at the link below 

[React Frontend ](https://github.com/liquify-validation/go-boundless.git)
