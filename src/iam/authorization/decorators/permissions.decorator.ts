import { SetMetadata } from '@nestjs/common';
import { PermissionType } from '../permission.type';

export const PERMISSIONS_KEY = 'permissions';
export const Permissions = (...permisions: PermissionType[]) =>
  SetMetadata(PERMISSIONS_KEY, permisions);
