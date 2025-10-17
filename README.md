# SecureCloudVault
### Video Demo: [https://www.youtube.com/watch?v=IFYa83G72-o]

#### Description
SecureCloudVault is a file storage web application made with flask and python it allows users to upload safely, store and download files while keeping strong authentication and encryption.The goal was to gain skills on web development while combining concepts like encryption, database handling and multi-factor authentication(MFA) into a practical tool.Passwords are hashed when users register and a unique TOTP (time based one time password) secrect is generated for MFA.the user will then be required to scan a QR code using authenticator app like Google Authenticator or Authy. Every loging  attempt does not only require a password by also a 6 digit TOTP code as an extra layer of protection.Once authenticated users can upload files which are encrypted using a unique key per user.They are only decrypted when downloaded by the user but until then they are stored safely and securely on the server.Email are sent if suspicious activities like repeated failed logins occur. I used flask, SQLite, pyotp, cryptography(fernet), and SMTP for email alerts.Through this project l gained a better understanding of real world web app security concerns and how to mitigate them using layered defence

---
### Project Structure:
-**app.py**: Main application containing routes, models, and core logic.
-**init_db.py**: Initializes the database.
-**database.db**: SQLite database storing user and file info.
-**.env**: Stores environment variables like email credentials and encryption keys.
-**templates/**: HTML templates for pages such as  login, registration,MFA setup,  and file views.
-**uploads/**: Folder where encrypted user files are stored
-**requirements.txt**: Python dependencies list.
-**audit.log**: Log file for security-related events

---
### Key Features:
-Secure user registration with password hashing and MFA setup via QR code
-File uploads encrypted with unique keys, stored in user-specific folders.
-Secure downloads decrypt files on-the-fly.
-Email alerts for multiple failed login or MFA attempts to monitor potential breaches.
-Simple, user-friendly interface with clear navigation.

---
### How to Run:
1. Clone repo  and create .env with your SMTP info and  master encryption key.
2. Install dependencies using `pip install -r requirements.txt`.
3. Initialize the database: `python init_db.py`.
4. Run the app: `python app.py`.
5. Open `http://localhost:5000` in your browser.

---
This project combines secure authentication, encryption, and alerting to build a reliable file vault.it balances ease of use with strong security, making it a solid foundation for  a privacy-focused cloud storage app

