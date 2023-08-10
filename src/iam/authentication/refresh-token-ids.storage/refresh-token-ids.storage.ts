import {
  Inject,
  Injectable,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigType } from '@nestjs/config';
import { Redis } from 'ioredis';
import jwtConfig from 'src/iam/config/jwt.config';

export class InvalidatedRefreshTokenError extends Error {}

@Injectable()
export class RefreshTokenIdsStorage
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  constructor(
    @Inject(jwtConfig.KEY)
    private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
  ) {}
  private redisClient: Redis;
  onApplicationBootstrap() {
    // TODO: Ideally, we should move this to the dedicated "RedisModule"
    // instead of initiating the connection here.
    this.redisClient = new Redis({
      host: 'localhost', // NOTE: we should use the environment variables here
      port: 6379,
      password: 'abc1234',
    });
  }

  onApplicationShutdown(signal?: string) {
    return this.redisClient.quit();
  }

  async insert(userId: string, tokenId: string): Promise<void> {
    await this.redisClient.set(
      this.getKey(userId),
      tokenId,
      'EX',
      this.jwtConfiguration.accessTokenTtl / 1000,
    );
  }

  async insertToken(tokenId: string, refreshToken: string): Promise<void> {
    await this.redisClient.set(
      this.getTokenKey(tokenId),
      refreshToken,
      'EX',
      this.jwtConfiguration.refreshTokenTtl / 1000,
    );
  }

  async getToken(tokenId: string) {
    const token = await this.redisClient.get(this.getTokenKey(tokenId));
    return token;
  }

  async validate(userId: string, tokenId: string): Promise<boolean> {
    const storeId = await this.redisClient.get(this.getKey(userId));
    if (storeId !== tokenId) throw new InvalidatedRefreshTokenError();
    return storeId === tokenId;
  }

  async invalidate(userId: string): Promise<void> {
    await this.redisClient.del(this.getKey(userId));
  }

  private getKey(userId: string): string {
    return `user-${userId}`;
  }

  private getTokenKey(tokenId: string): string {
    return `token-${tokenId}`;
  }
}
