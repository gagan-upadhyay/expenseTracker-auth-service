import jwt from 'jsonwebtoken';

export default function tokenSetter(id){
    const accessToken = jwt.sign({id}, process.env.SECRET,{expiresIn:process.env.ACCESS_EXPIRY});
    const refreshToken = jwt.sign({id}, process.env.REFRESH_SECRET,{expiresIn:process.env.REFRESH_EXPIRY});
    return {accessToken, refreshToken};

}