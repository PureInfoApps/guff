import UserModel from '@/models/user';
import { IUser, IUserInputDTO, UserRole } from '@/interfaces/IUser';
import { Service } from 'typedi';

@Service()
export class UserRepository {
  constructor() {}

  public isAdminExisting = async (): Promise<boolean> => {
    const record = await UserModel.findOne({ where: { role: UserRole.ADMIN } });
    return record != null;
  };

  public createUser = async (userInputDTO: IUserInputDTO, salt: IUser['salt'], role: IUser['role']): Promise<IUser> => {
    return UserModel.create(
      {
        ...userInputDTO,
        salt,
        role,
      },
      { raw: true },
    ).then(result => result.toJSON());
  };

  public findUserByUsername = async (username: IUser['username']): Promise<IUser> => {
    return (await UserModel.findOne({ where: { username } })).get();
  };

  public updateUser = async (
    username: IUser['username'],
    newPassword: IUser['password'],
    newSalt: IUser['salt'],
  ): Promise<IUser> => {
    const update = await UserModel.update(
      { password: newPassword, salt: newSalt },
      { where: { username }, returning: true },
    );

    return update && update[1] && update[1].length > 0 && update[1][0].get();
  };
}
