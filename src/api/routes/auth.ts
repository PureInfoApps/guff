import { Router } from 'express';
import { Container } from 'typedi';
import middlewares from '../middlewares';
import { celebrate, Joi } from 'celebrate';
import { AuthController } from '../controllers/authController';

const route = Router();

export default (app: Router) => {
  const ctrl: AuthController = Container.get(AuthController);
  app.use('/auth', route);

  const validations = {
    username: Joi.string().required().label('Username'),
    email: Joi.string().email().label('Email'),
    password: Joi.string().min(3).max(30).required().label('Password'),
    password_confirmation: Joi.any().equal(Joi.ref('password')).required().label('Confirm Password'),
  };

  route.post(
    '/create',
    celebrate({
      body: Joi.object({
        username: validations.username,
        email: validations.email,
        password: validations.password,
        password_confirmation: validations.password_confirmation,
      }),
    }),
    ctrl.createServer,
  );

  route.post(
    '/join',
    celebrate({
      body: Joi.object({
        username: validations.username,
        email: validations.email,
        password: validations.password,
        password_confirmation: validations.password_confirmation,
      }),
    }),
    ctrl.joinServer,
  );

  route.post(
    '/signin',
    celebrate({
      body: Joi.object({
        username: validations.username,
        password: validations.password,
      }),
    }),
    ctrl.signin,
  );

  route.post(
    '/change',
    middlewares.isAuth,
    celebrate({
      body: Joi.object({
        password: validations.password,
      }),
    }),
    ctrl.change,
  );

  route.post(
    '/reset',
    middlewares.isAdminAuth,
    celebrate({
      body: Joi.object({
        username: validations.username,
        password: validations.password,
      }),
    }),
    ctrl.reset,
  );
};
