import { IUser, UserRole } from '@/interfaces/IUser';
import sequelize from '../loaders/postgres';
import { DataTypes, Model } from 'sequelize';

const User = sequelize.define<Model & IUser>(
  'user',
  {
    username: {
      type: DataTypes.STRING,
      primaryKey: true,
    },
    email: {
      type: DataTypes.STRING,
      allowNull: true,
      validate: {
        isEmail: true,
      },
      unique: true,
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    salt: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    role: {
      type: DataTypes.ENUM,
      allowNull: false,
      values: [UserRole.ADMIN, UserRole.USER],
      defaultValue: UserRole.USER,
    },
  },
  {
    timestamps: true,
  },
);

export default User;
