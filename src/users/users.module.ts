import { UserRepository } from './repository/users.repository';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Module } from '@nestjs/common';
import { UsersService } from './users.service';

@Module({
    imports: [TypeOrmModule.forFeature([UserRepository])],
    providers: [UsersService],
})
export class UsersModule {}
