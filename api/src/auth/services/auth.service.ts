import { v4 as uuidv4 } from 'uuid';
import { BadRequestException, UnauthorizedException, Injectable } from '@nestjs/common';
import { translationKeys, EncryptionService } from 'src/common';
import { UserDocument, UserRole, UserService } from 'src/user';
import { LoginDto, RegisterDto, TokenResponseDto } from '../dtos';
import { TokenService } from './token.service';
import { JwtService } from '@nestjs/jwt';


const EMAIL_ALREADY_EXISTS: string = translationKeys.auth.emailAlreadyExists;
const INVALID_CREDENTIALS: string = translationKeys.auth.invalidCredentials;

@Injectable()
export class AuthService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly userService: UserService,
    private readonly encryptionService: typeof EncryptionService, 
    private readonly tokenService: TokenService,
  ) {}




  async loginWithTokens(user: any) {
    const payload = { username: user.username, sub: user.userId };
    return {
      accessToken: this.jwtService.sign(payload, {
        secret: 'access-token-secret',
        expiresIn: '15m', // expires in 15 minutes
      }),
      refreshToken: this.jwtService.sign(payload, {
        secret: 'refresh-token-secret',
        expiresIn: '7d', // expires in 7 days
      }),
    };
  }

  async login(dto: LoginDto): Promise<TokenResponseDto> {
    const { email, password } = dto;
    const user = await this.userService.findOne({ email });

    if (!user) {
      throw new UnauthorizedException(INVALID_CREDENTIALS);
    }

    const isPasswordValid = await this.encryptionService.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException(INVALID_CREDENTIALS);
    }

    return this.tokenService.issueToken({
      id: user.id,
      email: user.email,
      role: user.role,
    });
  }
  

  


  async generateAccessToken(user: any) {
    const payload = { username: user.username, sub: user.userId };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }

  async generateRefreshToken(user: any) {
    const payload = { username: user.username, sub: user.userId };
    return {
      refresh_token: this.jwtService.sign(payload, { expiresIn: '7d' }), // Refresh token with longer validity
    };
  }

  async getNewAccessToken(refreshToken: string) {
    // Verify the refresh token, extract payload, and generate a new access token
    try {
      const payload = this.jwtService.verify(refreshToken, { secret: 'yourSecretKey' });
      return this.generateAccessToken({ username: payload.username, userId: payload.sub });
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }








  async register(dto: RegisterDto): Promise<TokenResponseDto> {
    const { email, password, firstName, lastName } = dto;

    const hashedPassword = await EncryptionService.hash(password);
    const userExists: boolean = await this.userService.doesUserWithEmailExist(email);

    if (userExists) {
      throw new BadRequestException(EMAIL_ALREADY_EXISTS);
    }

    const user: UserDocument = await this.userService.create({
      email,
      firstName,
      lastName,
      password: hashedPassword,
      role: UserRole.customer,
    });

    return this.tokenService.issueToken({
      id: user.id,
      email: user.email,
      role: user.role,
    });
  }

 






  public async issueAnonymousToken(): Promise<TokenResponseDto> {
    return this.tokenService.issueToken({
      id: uuidv4(),
      role: UserRole.anonymous,
    });
  }
}
