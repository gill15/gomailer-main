import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { UserModule } from './user';
import { AuthModule } from './auth';
import environment from './environment';

@Module({
  imports: [MongooseModule.forRoot(environment.mongodb), UserModule, AuthModule],
  controllers: [],
  providers: [],
})
export class AppModule {}
