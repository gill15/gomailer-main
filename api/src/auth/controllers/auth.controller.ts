import { Body, Controller, Post, Req, Res, UnauthorizedException, Injectable } from '@nestjs/common';
import { AuthService } from '../services';
import { LoginDto, RegisterDto, TokenResponseDto } from '../dtos';
import { ApiBody, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Response } from 'express';
import { JwtService } from '@nestjs/jwt';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService,
              private jwtService: JwtService) {}



  @Post('loginWithTokens')
  async loginWithTokens(@Req() req, @Res({ passthrough: true }) response: Response) {
    const { refreshToken, accessToken } = await this.authService.login(req.user);
    // Set refresh token in httpOnly cookie
    response.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      path: '/auth/refresh',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    return { accessToken };
  }




  @Post('refresh')
  async refreshAccessToken(@Body('refreshToken') refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: process.env.JWT_REFRESH_SECRET, // Use a separate secret for refresh tokens
      });

      // Optionally, add additional checks here (e.g., token blacklist, database checks)

      // Issue new access token
      const accessToken = this.jwtService.sign({ userId: payload.userId });
      return { accessToken };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }




  @Post('login')
  @ApiBody({ type: LoginDto })
  @ApiResponse({ status: 200, description: 'Return auth & refresh token', type: TokenResponseDto })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  public async login(@Body() dto: LoginDto): Promise<TokenResponseDto> {
    return this.authService.login(dto);
  }

  @Post('register')
  @ApiBody({ type: RegisterDto })
  @ApiResponse({ status: 200, description: 'Return auth & refresh token', type: TokenResponseDto })
  @ApiResponse({ status: 400, description: 'User already exists' })
  public async register(@Body() dto: RegisterDto): Promise<TokenResponseDto> {
    return this.authService.register(dto);
  }
}
