const sameSiteVal = process.env.NODE_ENV==='development'?'None':'Strict';

export function setAuthCookie(res, refreshToken, accessToken, isLoggedIn){
    
    res.cookie('refreshToken', refreshToken, {
        maxAge: 7 * 24 * 3600 * 1000, // 7 days
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        path: '/'
    });

    res.cookie('accessToken', accessToken, {
        maxAge:15 * 60 * 1000,  // 15 min
        httpOnly: true,         // accessible to JS for middleware
        secure: true,
        sameSite: 'Strict',
        path: '/'
    });
    // res.cookie('isLoggedIn', isLoggedIn, {

    // })
}

export function deleteAuthCookie(res){
    res.clearCookie('accessToken', {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        path: '/',
    });
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: true,
        sameSite: 'Strict',
        path: '/',
    });
}