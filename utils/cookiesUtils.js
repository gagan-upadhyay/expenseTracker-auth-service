const isProduction = process.env.NODE_ENV === 'production';

export function setAuthCookie(res, refreshToken, accessToken){
    
    res.cookie('refreshToken', refreshToken, {
        maxAge: 7 * 24 * 3600 * 1000, // 7 days
        httpOnly: true,
        secure: isProduction, // localhost=HTTP => false
        sameSite:isProduction?"none":'lax', // required
        path: '/'
    });

    
    res.cookie('accessToken', accessToken, {
        maxAge:15 * 24 * 3600 * 1000,  // 15 min
        httpOnly: true,         // accessible to JS for middleware
        secure: isProduction, // localhost=HTTP => false
        sameSite: isProduction?'none':'lax', // required
        path: '/'
    });
    // res.cookie('isLoggedIn', isLoggedIn, {

    // })
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