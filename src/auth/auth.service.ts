import { HttpStatus, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { throwRpc } from 'src/common/errors';
import { envs } from 'src/config';
import { LoginUserDto, RegisterUserDto } from './dto';
import { JwtPayload, Registered } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
    this.logger.log('MongoDB connected');
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { email, name, password } = registerUserDto;

    try {
      const user = await this.user.findUnique({
        where: { email },
      });

      if (user) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'User already exists',
        });
      }

      const newUser = await this.user.create({
        data: {
          email: email,
          name: name,
          password: bcrypt.hashSync(password, 10),
        },
      });

      // Evita devolver el password
      const { password: _omit, ...safeUser } = newUser;

      return {
        user: safeUser,
        token: await this.signJWT(safeUser),
      };
    } catch (error) {
      throwRpc(error);
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      const user = await this.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'User/Password not valid',
        });
      }
      const isPasswordValid = bcrypt.compareSync(password, user.password);

      if (!isPasswordValid) {
        throw new RpcException({
          status: HttpStatus.BAD_REQUEST,
          message: 'User/Password not valid',
        });
      }
      // Evita devolver el password
      const { password: _omit, ...safeUser } = user;

      return {
        user: safeUser,
        token: await this.signJWT(safeUser),
      };
    } catch (error) {
      throwRpc(error);
    }
  }

  async verifyToken(token: string) {
    try {
      const payload = await this.jwtService.verifyAsync<
        JwtPayload & Registered
      >(token, {
        secret: envs.JWT_SECRET,
      });

      const { sub: _sub, iat: _iat, exp: _exp, ...user } = payload;

      return {
        user: user,
        token: await this.signJWT(user),
      };
    } catch (_error) {
      throwRpc('Token not valid', HttpStatus.UNAUTHORIZED);
    }
  }

  private async signJWT(payload: JwtPayload) {
    return this.jwtService.signAsync(payload);
  }
}
