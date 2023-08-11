import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Res,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { Response } from 'express';
import { AuthenticationService } from './authentication.service';
import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { Auth } from './decorators/auth.decorator';
import { AuthType } from './enums/auth-type.enum';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ActiveUser } from '../decorators/active-user.decorator';
import { ActiveUserData } from '../interfaces/active-user-data.interface';
import { OtpAuthenticationService } from './otp-authentication.service';
import { toFileStream } from 'qrcode';
import { AccessTokenGuard } from './guards/access-token.guard';

@Auth(AuthType.None)
@UseInterceptors(ClassSerializerInterceptor)
@Controller('authentication')
export class AuthenticationController {
  constructor(
    private readonly otpAuthService: OtpAuthenticationService,
    private readonly authService: AuthenticationService,
  ) {}

  @UseGuards(AccessTokenGuard)
  @Get('user')
  getCurrentUser(@ActiveUser() activeUser: ActiveUserData) {
    return activeUser;
  }

  @Post('sign-up')
  signUp(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('sign-in')
  async signIn(
    @Res({ passthrough: true }) response: Response,
    @Body() signInDto: SignInDto,
  ) {
    const { accessToken, refreshToken, refreshTokenId } =
      await this.authService.signIn(signInDto);
    const cookieExpireTime = new Date(Date.now() + 2 * (60 * 60 * 1000));
    response
      .cookie('accessToken', accessToken, {
        secure: true,
        httpOnly: true,
        sameSite: true,
        expires: cookieExpireTime,
      })
      .cookie('refreshToken', refreshTokenId, {
        secure: true,
        httpOnly: true,
        sameSite: true,
        expires: cookieExpireTime,
      });
    return { accessToken, refreshToken };
  }

  @HttpCode(HttpStatus.OK)
  @Post('refresh-tokens')
  async refreshTokens(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshTokens(refreshTokenDto);
  }

  @Auth(AuthType.Bearer)
  @HttpCode(HttpStatus.OK)
  @Post('2fa/generate')
  async generateQrCode(
    @ActiveUser() activeUser: ActiveUserData,
    @Res() response: Response,
  ) {
    const { secret, uri } = await this.otpAuthService.generateSecret(
      activeUser.email,
    );
    await this.otpAuthService.enableTfaForUser(activeUser.email, secret);
    response.type('png');
    return toFileStream(response, uri);
  }
}
