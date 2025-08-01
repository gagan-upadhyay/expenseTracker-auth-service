import { body, validationResult, param } from "express-validator";

export const registerValidator = async(req, res, next)=>{
    const rule=[
        body('firstName').notEmpty().isLength({min:3}).withMessage("Username is required with minimum length 3"),
        body('lastName').optional(),
        body('email').isEmail().notEmpty().withMessage("Enter valid email"),
        body('password').withMessage(),
        body('gender').withMessage(),
    ]
}

await Promise.all(rule.map(r=>r.run(req)))
validationResult(req);