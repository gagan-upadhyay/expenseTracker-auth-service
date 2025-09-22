import { createTransport } from "nodemailer";
import { logger } from "../config/logger.js";
import {validate } from "./emailValidator.js";



export const sendOTPEmail = async (name, email, otp)=>{
    console.log("Value of name, email, otp from sendOTP utility:\n", name, email, otp);
    const isValid = await validate(email);
    
    console.log("Value of isValid\n", isValid);

    if(!isValid){
        return 'Email is not valid';
    }
    
    const transporter = createTransport({
        service:process.env.EMAIL_SERVICE,
        auth:{
            user:process.env.EMAIL_USER,
            pass:process.env.EMAIL_PASS,
        },
    });

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