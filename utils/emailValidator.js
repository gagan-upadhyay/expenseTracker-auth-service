import {EmailValidator} from "robust-email-validator";

const validator = new EmailValidator({
    checkFormat:true,
    checkDNS:true,
    checkDeliverability:false
});

export async function validate(email){
    const result = await validator.validate(email);
    console.log(result.isValid);
    return result.isValid;
}