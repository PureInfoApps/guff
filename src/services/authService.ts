import { Inject, Service } from 'typedi';
import jwt from 'jsonwebtoken';
import config from '@/config';
import argon2 from 'argon2';
import { randomBytes } from 'crypto';
import { IUser, IUserInputDTO, UserRole } from '@/interfaces/IUser';
import { UserRepository } from '@/repositories/userRepository';
import { Logger } from 'winston';
import capitalizeFirstLetter from '@/utils/StringUtils/capitalizeFirstLetter';

@Service()
export default class AuthService {
  protected userRepositoryInstance: UserRepository;
  constructor(@Inject('logger') private logger: Logger, userRepository: UserRepository) {
    this.userRepositoryInstance = userRepository;
  }

  public async adminSignup(userInputDTO: IUserInputDTO) {
    // A server can have only one ADMIN exists.
    const isAdminExisting = await this.userRepositoryInstance.isAdminExisting();
    if (isAdminExisting) throw 'A server already exists, please join one.';

    if (!userInputDTO.email) throw 'The server admin must have an email.';

    return this.signUp(userInputDTO, UserRole.ADMIN);
  }

  public async userSignup(userInputDTO: IUserInputDTO) {
    // A server must have an ADMIN before users can join in.
    const isAdminExisting = await this.userRepositoryInstance.isAdminExisting();
    if (!isAdminExisting) throw 'No server exists on this instance, please create one.';

    return this.signUp(userInputDTO, UserRole.USER);
  }

  private async signUp(userInputDTO: IUserInputDTO, role: IUser['role']): Promise<{ user: IUser; token: string }> {
    try {
      const { salt, hashedPassword } = await this.hashPassword(userInputDTO.password);

      this.logger.silly('Creating user db record');

      const userRecord = await this.userRepositoryInstance
        .createUser(
          { ...userInputDTO, password: hashedPassword, password_confirmation: undefined },
          salt.toString('base64'),
          role,
        )
        .catch(error => {
          if (error.name === 'SequelizeUniqueConstraintError' && error?.errors?.length > 0)
            throw capitalizeFirstLetter(error.errors[0].message);
          throw error;
        });

      this.logger.silly('Generating JWT');

      const token = this.generateToken(userRecord);

      if (!userRecord) throw 'User cannot be created';
      const user = { ...userRecord };
      Reflect.deleteProperty(user, 'password');
      Reflect.deleteProperty(user, 'salt');

      return { user, token };
    } catch (e) {
      throw e;
    }
  }

  public async signIn(
    username: IUserInputDTO['username'],
    password: IUserInputDTO['password'],
  ): Promise<{ user: IUser; token: string }> {
    const userRecord = await this.userRepositoryInstance.findUserByUsername(username);
    if (!userRecord) throw new Error('User not registered');

    /**
     * We use verify from argon2 to prevent 'timing based' attacks
     */
    this.logger.silly('Checking password');

    const validPassword = await argon2.verify(userRecord.password, password, {
      salt: Buffer.from(userRecord.salt, 'base64'),
    });
    if (validPassword) {
      this.logger.silly('Password is valid!');
      this.logger.silly('Generating JWT');
      const token = this.generateToken(userRecord);

      const user = { ...userRecord };
      Reflect.deleteProperty(user, 'password');
      Reflect.deleteProperty(user, 'salt');
      return { user, token };
    } else {
      throw new Error('Invalid Password');
    }
  }

  public async changePassword(username: IUser['username'], newPassword: IUser['password']) {
    // This is a protected route called by the one who is changing the password themselves (Not even ADMIN can call this for their user, they need to use "resetPassword" route for that).

    const { salt, hashedPassword } = await this.hashPassword(newPassword);

    this.logger.silly('Updating user db record');
    const update = await this.userRepositoryInstance.updateUser(username, hashedPassword, salt.toString('base64'));

    const user = { ...update };

    this.logger.silly('Generating JWT');
    const token = this.generateToken(user);

    Reflect.deleteProperty(user, 'password');
    Reflect.deleteProperty(user, 'salt');

    return { user, token };
  }

  public async resetPassword(username: IUser['username'], newPassword: IUser['password']) {
    // This is a protected route which can be only called by ADMINS and hence admins can reset the password for any/every user.
    try {
      const userRecord = await this.userRepositoryInstance.findUserByUsername(username);
      if (!userRecord) throw 'The user is not registered';

      // If ADMINS forget their password, there is no way to recover it 😞
      if (userRecord.role == UserRole.ADMIN) {
        throw 'Sorry, this action is not allowed for server admins.';
      }

      const { user, token } = await this.changePassword(username, newPassword);

      return { user, token };
    } catch (error) {
      throw error;
    }
  }

  private hashPassword = async (password: string) => {
    this.logger.silly('Hashing password and creating salt');

    const salt = randomBytes(32);

    const hashedPassword = await argon2.hash(password, { salt });

    return { salt, hashedPassword };
  };

  private generateToken(user: IUser) {
    const today = new Date();
    const exp = new Date(today);
    exp.setTime(today.getTime() + 1000 * 60 * 60 * 24 * 10); //10 days

    /**
     * A JWT means JSON Web Token, so basically it's a json that is _hashed_ into a string
     * The cool thing is that you can add custom properties a.k.a metadata
     * Here we are adding the userId, role and name
     * Beware that the metadata is public and can be decoded without _the secret_
     * but the client cannot craft a JWT to fake a userId
     * because it doesn't have _the secret_ to sign it
     * more information here: https://softwareontheroad.com/you-dont-need-passport
     */
    this.logger.silly(`Sign JWT for username: ${user.username}`);
    const token = jwt.sign(
      {
        role: user.role,
        username: user.username,
        email: user.email,
        exp: exp.getTime() / 1000,
      },
      config.jwtSecret,
    );
    return `Bearer ${token}`;
  }
}
