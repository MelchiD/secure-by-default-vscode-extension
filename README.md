secure-by-default-extension README
## Important Notice

The folder submitted with this project contains only the source code (src/) of the extension and does not include the complete packaged extension.

The full working extension package has been shared separately with Dr. Chinnu Mary and also CC: to my supervisors via outlook with a OneDrive link.

Due to submission size limitations, it is strongly recommended to:

Use the OneDrive version for testing and demonstration, as it contains all compiled files and dependencies required to run the extension properly.

## Project Overview

The Secure-by-Default Extension is a Visual Studio Code extension designed to detect insecure default configurations in Express.js applications.

It provides real-time security feedback by analysing code using Abstract Syntax Tree (AST) parsing and a rule-based detection engine.

The goal is to help developers identify and fix security misconfigurations during development, rather than after deployment.

## Features
Real-time detection of insecure configurations
Express.js-specific security rules
Lightweight and developer-friendly
Integration with VS Code Problems panel

## Implemented Rules
Missing Helmet middleware
Permissive CORS configuration
Insecure session settings
Missing rate limiting
Missing JSON body size limits
Missing upload size limits
X-Powered-By header exposure
Open redirect vulnerability
Trust proxy misconfiguration
Overly broad static file paths

## How to Run the Extension
## Prerequisites
Node.js installed
Visual Studio Code installed

## Steps to Run
Open the project folder in Visual Studio Code

Ensure dependencies are installed:

npm install
Press F5

## This will:

Launch a new Extension Development Host window
Activate the extension automatically

## Testing the Extension

Inside the folder conntains secure.js and insecure.js copy them from the main folder and paste into the new VS Code window:

Open the provided test files:
insecure.js
secure.js
Observe results in:
# Problems Panel
# Test Files

insecure.js
Contains intentionally insecure configurations to trigger warnings:

cors() without restrictions
missing Helmet
insecure session settings
no rate limiting
\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

secure.js
Contains properly configured security settings:

Helmet enabled
restricted CORS
secure session configuration
defined request limits
⚙️ How It Works
The extension listens for file events (open/edit)
JavaScript code is parsed using AST
Custom security rules analyse the code
Issues are displayed in real-time in the Problems panel

## Expected Output
Insecure files : warnings generated
Secure files : no warnings

## Additional Notes

For full functionality and accurate testing:
Please use the OneDrive version shared with Dr. Chinnu Mary, as it contains the complete extension build.