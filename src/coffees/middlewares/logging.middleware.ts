import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthenticationService } from 'src/iam/authentication/authentication.service';
import { RefreshTokenIdsStorage } from 'src/iam/authentication/refresh-token-ids.storage/refresh-token-ids.storage';

@Injectable()
export class LoggingMiddleware implements NestMiddleware {
  constructor(
    private readonly authenticationService: AuthenticationService,
    private readonly refreshTokenIdsStorage: RefreshTokenIdsStorage,
  ) {}
  async use(req: Request, res: Response, next: () => void) {
    try {
    } catch (error) {
      console.log(error, '...here...');
    } finally {
      next();
    }
  }
}
