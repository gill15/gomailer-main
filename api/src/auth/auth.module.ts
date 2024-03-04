import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService, TokenService } from './services';
import environment from 'src/environment';
import { UserModule } from 'src/user';
import { AuthController } from './controllers';


@Module({
  controllers: [AuthController],
  imports: [
    JwtModule.register({
      global: true,
      secret: environment.jwtOptions.secret,
      signOptions: { expiresIn: '60s' }, 
    }),
    UserModule,
  ],
  providers: [AuthService, TokenService],
  exports: [AuthService],
 
  
})
export class AuthModule {}
