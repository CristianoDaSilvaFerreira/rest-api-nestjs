import { UserRole } from './../users/Enum/users.service';
import { User } from './../users/entities/user.entity';
import { CreateUserDto } from './../users/dtos/create-user.dto';
import { UserRepository } from './../users/repository/users.repository';
import { Injectable, UnprocessableEntityException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserRepository)
    private userRepository: UserRepository,
  ) {}

  //   Método para criação de usuário comum
  async signUp(createUserDto: CreateUserDto): Promise<User> {
    if (createUserDto.password != createUserDto.passwordConfirmation) {
      throw new UnprocessableEntityException('As senhas não conferem');
    } else {
      return await this.userRepository.createUser(createUserDto, UserRole.USER);
    }
  }
}
