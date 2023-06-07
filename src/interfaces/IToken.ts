import { IUser } from './IUser';

export interface IToken {
  username: IUser['username'];
  email?: IUser['email'];
  role: IUser['role'];
  exp?: number;
  iat?: number;
}
