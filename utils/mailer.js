import { createTransport } from "nodemailer";
import { logger } from "../config/logger.js";
import {validate } from "./emailValidator.js";

const transporter = createTransport({
        service:process.env.EMAIL_SERVICE,
        auth:{
            user:process.env.EMAIL_USER,
            pass:process.env.EMAIL_PASS,
        },
    });

export const sendOTPEmail = async (name, email, otp)=>{
    console.log("Value of name, email, otp from sendOTP utility:\n", name, email, otp);
    const isValid = await validate(email);
    
    if(!isValid){
        return 'Email is not valid';
    }
    
    

    const mailOptions = {
        from:process.env.EMAIL_USER,
        to:email,
        subject:`Hey ${name}, here is your OTP ${otp}`,
        html:
        `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Expense Tracker API</title>
                <style>
                    /* Add your custom CSS styles here */
                    body {
                        font-family: Arial, sans-serif;
                    }
                    .container {
                        max-width: 600px;
                        margin: 0 auto;
                        padding: 20px;
                    }
                    .header {
                        text-align: center;
                    }
                    .logo {
                        max-width: 150px;
                    }
                    .content {
                        margin-top: 20px;
                    }
                    .button {
                        display: inline-block;
                        padding: 10px 20px;
                        background-color: #20d49a;
                        color: #ffffff;
                        text-decoration: none;
                        border-radius: 5px;
                    }
                    /* Mobile Responsive Styles */
                    @media only screen and (max-width: 600px) {
                        .container {
                            padding: 10px;
                        }
                        .logo {
                            max-width: 100px;
                        }
                        .button {
                            display: block;
                            margin-top: 10px;
                        }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <img class="logo" src="https://raw.githubusercontent.com/gagan-upadhyay/expenseTracker-auth-service/main/images/logo-removebg-preview.png" alt="Expense Tracker Api">
                        <h1>Welcome to the ExpenseTracker API</h1>
                    </div>
                    <div class="content">
                        <p>Hello ${name},</p>
                        <p>The OTP for your authentication is <h1><strong>${otp}</strong></h1></p>
                    </div>
                </div>
            </body>
            </html>
        `

    }

    try{
        // const result = await transporter.verify();
        // console.log("Value of result from mailer:\n", result);
        const result = await transporter.sendMail(mailOptions);
        // console.log("VBalue of result from mailer:", result);
        logger.info(`OTP mail sent to ${email}`);
        return 'OTP sent Successfully!';
    }catch(err){
        logger.error(`Error in sending OTP mail to user ${email}`, err);
        throw new Error (`Couldn\'t send OTP mail to user ${name} with ${email}`);
    }
};

export const sendPasswordMagicLink = async(email, token)=>{
    const isValid = await validate(email);
    
    if(!isValid){
        return 'Email is not valid';
    }

    const mailOptions={
        from:process.env.EMAIL_USER,
        to:email,
        subject:"Expense Tracker App | Password reset Magic Link",
        html:
        `
        
            <!DOCTYPE html>
            <html>
            <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {
                font-family: Arial, sans-serif;
                background-color: #f9f9f9;
                color: #333;
                margin: 0;
                padding: 0;
                }
                .container {
                max-width: 600px;
                margin: 20px auto;
                background: #ffffff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                }
                h2 {
                color: #2c3e50;
                }
                p {
                line-height: 1.6;
                }
                .button {
                display: inline-block;
                padding: 12px 20px;
                margin: 20px 0;
                background-color: #0078D4;
                color: #ffffff;
                text-decoration: none;
                border-radius: 4px;
                font-weight: bold;
                }
                .footer {
                font-size: 12px;
                color: #777;
                margin-top: 20px;
                }
            </style>
            </head>
            <body>
            <div class="container">
                <h2>Password Reset Request</h2>
                <p>Hello User,</p>
                <p>We received a request to reset your password for your <strong>Expense Tracker App</strong> account.</p>
                <p>Click the button below to set a new password:</p>

                <p>
                <a href="http://localhost:3000/api/v1/auth/password-reset/validate?token=${token}">Reset Your Password</a>
                </p>

                <p>This link will expire in <strong>15 minutes</strong> and can only be used once.</p>
                <p>If you did not request this change, please ignore this email or contact our support team immediately.</p>
                <p class="footer">
                For your security: Do not share this link with anyone. Make sure you are on <strong>http://localhost:3000</strong> before entering your new password.
                </p>
                <p class="footer">Thank you,<br>The Expense Tracker Team</p>
            </div>
            </body>
            </html>


        `
    }

    try{
        const result = await transporter.sendMail(mailOptions);
        logger.info(`Magic link sent to email: ${email}`)
        return 'magic link sent successfully';
    }catch(err){
        logger.error(`Error while sending magic link to email: ${email}`);
        throw new Error(`Couldn'\t send magic link to user with email: ${email}`);
    }
    
}