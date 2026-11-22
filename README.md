# AI-CarCare-Advisor
AI-Powered web platform for vehicle maintenance tracking and troubleshooting - SWE 401 Course Project

• Project title
- AI CarCare Advisor

  
• Team members
- Abdulrahman Naji Ghazy
- Saif Alzaabi

  
• Problem
Many drivers don't know what a warning light or a strange noise means. They guess, ask family, or trust a garage they don't know, so small faults get ignored until they become expensive or unsafe. Apps like FIXD, CARFAX Car Care and Carly offer reminders and fault codes, but they don't explain problems in plain language. AI CarCare Advisor lets a non-expert describe a symptom in their own words and get the likely causes, what to do next, and how urgent it is.


• Key features
- Accounts: register, log in, reset your password with a single-use link that lasts 30 minutes, and delete your account along with all its data. The account locks for 15 minutes after 5 failed logins.
- Vehicles: one account can hold several vehicles, each with make, model, year, mileage and fuel type.
- Maintenance history: covers 9 service types, shows the newest first and can be filtered by type.
- Reminders: you get one when a service is within 500 km or 14 days. It shows on the dashboard and also goes to a demo email inbox. You can snooze it for 7 days or mark it done.
- Troubleshooting: type a symptom or pick a warning light, then answer up to 5 follow-up questions. You get up to 3 ranked causes, each with an action and a cost range.
- Urgency: every result is rated Low, Medium or High. Problems with brakes, steering, overheating or loss of power are always rated High and come with a stop-driving warning. Every result shows a disclaimer.
- Used-car evaluation: gives a condition score from 0 to 100, a price assessment, risk flags and a checklist to use before buying.
- Reports: you can download a PDF or share a read-only link that expires after 7 days.
- Admin panel: admins manage users, service intervals, warning lights and symptom causes without changing any code.


• Technologies
- HTML, CSS and plain JavaScript, with no frameworks or external libraries
- Browser localStorage as the data store 
- A rule-based knowledge base engine for diagnosis and urgency
- Salted SHA-256 password hashing
- A simulated email inbox in place of a mail server
- Visual Studio Code and GitHub

  
• Prerequisites
- A recent version of Chrome, Edge, Firefox or Safari
- Git (optional, for cloning)
- Python 3 or the VS Code Live Server extension (optional, for serving the app locally)

  
• Installation
There's nothing to install. You can also use Code > Download ZIP on GitHub and unzip it.


• Configuration
The app needs no environment variables or API keys.
- Settings are constants at the top of `script.js`. They include `DAILY_LIMIT` (20 diagnoses per user per day), `DISCLAIMER` and `SAFETY_WORDS`.
- `defaultKb()` sets up the starting service intervals, warning lights and causes. Admins can change these from the admin panel while the app is running.
- Default admin login: `admin@carcare.demo` / `Admin@2026`. Change it before any real use.
- To reset all data, clear the site's local storage in your browser's dev tools.


• How to run
open `AICarCareAdvisor.html` in your browser or VScode


• How to test
1. Register an account, then try registering the same email again. You should see "An account with this email already exists".
2. Enter a wrong password 5 times. The account should lock for 15 minutes.
3. Add a 2018 Toyota Camry (85,000 km, Petrol), then add a second vehicle. Both should appear in the account.
4. Add an oil change with a date and mileage. The history should list it first.
5. Update the mileage so the oil change is due within 500 km. A reminder should appear on the dashboard and an email in the demo inbox.
6. Troubleshoot "squeaking sound when braking". You should get follow-up questions, then up to 3 ranked causes with actions.
7. Troubleshoot "car loses power on the motorway". It should be rated High urgency with a red stop-driving message.
8. Check that every result shows the disclaimer.
9. Log in as admin and change a service interval. The due dates should update with no code change.
10. Delete the account. You should no longer be able to log in.
