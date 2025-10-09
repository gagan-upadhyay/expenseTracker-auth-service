

import {
  registerUserService,
  loginUserService,
  registerUserWithOAuthService,
  refreshTokenService,
  generateOTPService,
  verifyOTPService,
  logoutUserService,
  checkPasswordService
} from '../services/authService.js';

export const registerUser = (req, res) => registerUserService(req, res);
export const loginUser = (req, res) => loginUserService(req, res);
export const registerUserWithOAuth = (req, res) => registerUserWithOAuthService(req, res);
export const refreshToken = (req, res) => refreshTokenService(req, res);
export const logoutUser = (req, res) => logoutUserService(req, res); 
export const generateOTP = (req, res) => generateOTPService(req, res); //done
export const verifyOTP = (req, res) => verifyOTPService(req, res); //done
export const clientLogs = (req, res) =>clientLogsService(req, res)

export const checkPassword=(req, res)=> checkPasswordService(req, res);