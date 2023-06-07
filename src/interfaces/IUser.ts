export interface IUser {
  username: string;
  email?: string;
  role: UserRole;
  password: string;
  salt: string;
  createdAt: Date;
  updatedAt: Date;
}
export enum UserRole {
  ADMIN = 'ADMIN',
  USER = 'USER',
}
export interface IUserInputDTO {
  username: IUser['username'];
  email?: IUser['email'];
  password: IUser['password'];
  password_confirmation?: IUser['password'];
}
