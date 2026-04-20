const adminAuth = (req, res, next) => {
  const key = req.headers['x-admin-key'] || req.query.admin_key;
  const expected = process.env.ADMIN_API_KEY;
  if (!expected) return res.status(403).json({ success: false, message: 'Admin API key not configured' });
  if (!key || key !== expected) return res.status(401).json({ success: false, message: 'Unauthorized' });
  return next();
};

export default adminAuth;
