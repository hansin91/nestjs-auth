import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  UnauthorizedException,
} from '@nestjs/common';
import { Response } from 'express';

@Catch(UnauthorizedException)
export class TokenExpiredFilter implements ExceptionFilter {
  catch(exception: UnauthorizedException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    if (exception.message === 'jwt expired') {
      response.status(401).json({ message: 'Token has expired' });
    } else {
      response.status(401).json({ message: 'Unauthorized' });
    }
  }
}
