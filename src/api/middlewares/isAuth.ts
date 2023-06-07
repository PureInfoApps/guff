import { verify } from 'jsonwebtoken';
import config from '@/config';
import Container from 'typedi';
import { INextFunction, IRequest, IResponse } from '../types/express';
import { IToken } from '@/interfaces/IToken';
import { Logger } from 'winston';
import { UserRole } from '@/interfaces/IUser';

export const getTokenFromHeader = (req): string => {
  /**
   * @TODO Edge and Internet Explorer do some weird things with the headers
   * So I believe that this should handle more 'edge' cases ;)
   */
  if (
    (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Token') ||
    (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer')
  ) {
    return req.headers.authorization.split(' ')[1];
  }
  return null;
};

export const checkToken = (token: string, isAuth = true): IToken => {
  const Logger: Logger = Container.get('logger');
  if (!token && isAuth) throw 'Token malformed';
  try {
    const decoded = verify(token, config.jwtSecret, { algorithms: [config.jwtAlgorithm] });
    return decoded;
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      /** @TODO here, we reissue the token using the refresh token from the database  */
    }

    Logger.error('🔥 Error in verifying token: %o', err);
    throw err;
  }
};

const baseAuth = async (req: IRequest, res: IResponse, next: INextFunction, type: IToken['role']) => {
  const logger: Logger = Container.get('logger');

  try {
    const tokenFromHeader = getTokenFromHeader(req);
    const token = checkToken(tokenFromHeader);
    if (token.role != type) return next(getErrorMessage(type));
    logger.debug('User authenticated %o', token);

    req.currentUser = token;
    return next();
  } catch (error) {
    return next(error);
  }
};

const getErrorMessage = (authType: IToken['role']) => {
  switch (authType) {
    case UserRole.ADMIN:
      return 'This is an authenticated resource, you must be logged in as an server admin to access it.';
    default:
      return 'This is an authenticated resource, you must be logged in to access it.';
  }
};

const isAuth = async (req: IRequest, res: IResponse, next: INextFunction) => {
  return baseAuth(req, res, next, UserRole.USER);
};
export const isAdminAuth = async (req: IRequest, res: IResponse, next: INextFunction) => {
  return baseAuth(req, res, next, UserRole.ADMIN);
};

export default isAuth;
