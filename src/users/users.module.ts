import { PassportModule } from '@nestjs/passport';
import { UserRepository } from './repository/users.repository';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';

@Module({
    imports: [
        TypeOrmModule.forFeature([UserRepository]),
        PassportModule.register({ defaultStrategy: 'jwt' }),
    ],
    providers: [UsersService],
    controllers: [UsersController],
})
export class UsersModule {}
