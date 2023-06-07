import { IUserInputDTO } from '@/interfaces/IUser';
import AuthService from '@/services/authService';
import { NextFunction, Request, Response } from 'express';
import { Inject, Service } from 'typedi';
import { Logger } from 'winston';
import { Result } from '../util/result';
import { INextFunction, IRequest, IResponse } from '../types/express';

@Service()
export class AuthController {
  protected logger: Logger;
  protected authServiceInstance: AuthService;
  constructor(@Inject('logger') logger: Logger, authService: AuthService) {
    this.logger = logger;
    this.authServiceInstance = authService;
  }

  public createServer = async (req: Request, res: Response, next: NextFunction) => {
    this.logger.debug('Calling Create-Server endpoint with body: %o', {
      ...req.body,
      password: '***',
      password_confirmation: '***',
    });
    try {
      const { user, token } = await this.authServiceInstance.adminSignup(req.body as IUserInputDTO);
      return res.status(200).json(Result.success({ user, token }));
    } catch (error) {
      return next(error);
    }
  };

  public joinServer = async (req: Request, res: Response, next: NextFunction) => {
    this.logger.debug('Calling Join-Server endpoint with body: %o', {
      ...req.body,
      password: '***',
      password_confirmation: '***',
    });

    try {
      const { user, token } = await this.authServiceInstance.userSignup(req.body as IUserInputDTO);
      return res.status(200).json(Result.success({ user, token }));
    } catch (error) {
      return next(error);
    }
  };

  public signin = async (req: Request, res: Response, next: NextFunction) => {
    this.logger.debug('Calling Sign-In endpoint with body: %o', { ...req.body, password: '***' });
    try {
      const { username, password } = req.body;
      const { user, token } = await this.authServiceInstance.signIn(username, password);
      return res.json(Result.success<Object>({ user, token })).status(200);
    } catch (e) {
      return next(e);
    }
  };

  public change = async (req: IRequest, res: IResponse, next: INextFunction) => {
    this.logger.debug('Calling Reset Password engpoint with body: %o', { ...req.body, password: '***' });
    try {
      const username = req.currentUser.username;
      const { password } = req.body;

      const resul = await this.authServiceInstance.changePassowrd(username, password);
      return res.status(200).json(Result.success(resul));
    } catch (error) {
      return next(error);
    }
  };
  public reset = async (req: IRequest, res: IResponse, next: INextFunction) => {
    this.logger.debug('Calling Reset Password engpoint with body: %o', { ...req.body, password: '***' });
    try {
      const { username, password } = req.body;
      const { user, token } = await this.authServiceInstance.resetPassword(username, password);
      return res.status(200).json(Result.success({ user, token }));
    } catch (error) {
      return next(error);
    }
  };
}
