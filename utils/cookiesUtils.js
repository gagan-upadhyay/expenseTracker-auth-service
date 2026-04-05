const isProduction = process.env.NODE_ENV === 'production';

export function setAuthCookie(res, refreshToken, accessToken){
    
    res.cookie('refreshToken', refreshToken, {
        maxAge:process.env.REFRESH_COOKIE_EXPIRY,
        httpOnly: true,
        secure: isProduction, // localhost=HTTP => false
        sameSite:isProduction?"none":'lax', // required
        path: '/'
    });

    
    res.cookie('accessToken', accessToken, {
        maxAge:process.env.ACCESS_COOKIE_EXPIRY,
        httpOnly: true,         // accessible to JS for middleware
        secure: isProduction, // localhost=HTTP => false
        sameSite: isProduction?'none':'lax', // required
        path: '/'
    });
}

export function deleteAuthCookie(res){
    res.clearCookie('accessToken', {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction?'none':'lax',
        path: '/',
    });
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction?'none':'lax',
        path: '/',
    });
}