import { Role } from 'src/users/enums/role.enum';
import { PermissionType } from '../authorization/permission.type';

export interface ActiveUserData {
  sub: string;
  email: string;
  role: Role;
  permissions: PermissionType[];
}
