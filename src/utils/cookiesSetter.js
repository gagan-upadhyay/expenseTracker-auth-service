export default function setAuthCookie(res, refreshToken, accessToken){

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
    })
}