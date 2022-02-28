import { FindUsersQueryDto } from './dtos/find-users-query.dto';
import { UpdateUserDto } from './dtos/update-users.dto';
import { User } from './entities/user.entity';
import { GetUser } from './../auth/get-user.decorator';
import { CreateUserDto } from './dtos/create-user.dto';
import { ReturnUserDto } from './dtos/return-users.dto';
import {
  Controller,
  Post,
  Body,
  ValidationPipe,
  UseGuards,
  Get,
  Param,
  Patch,
  ForbiddenException,
  Delete,
  Query,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { AuthGuard } from '@nestjs/passport';
import { RolesGuard } from '../auth/roles.guard';
import { Role } from '../auth/role.decorator';
import { UserRole } from './Enum/user-roles.enum';
import { ApiOperation, ApiProperty, ApiTags } from '@nestjs/swagger';

@Controller('users')
@ApiTags('REST API NestJs')
@UseGuards(AuthGuard(), RolesGuard)
export class UsersController {
  constructor(private usersService: UsersService) {}

  // Endpoint de criação de usuários
  @Post()
  @ApiOperation({ summary: 'Criar um usário' })
  @Role(UserRole.ADMIN)
  async createAdminUser(
    @Body(ValidationPipe) createUserDto: CreateUserDto,
  ): Promise<ReturnUserDto> {
    const user = await this.usersService.createAdminUser(createUserDto);
    return {
      user,
      message: 'Administrador cadastrado com sucesso',
    };
  }

  // Endpoint de buscar de usuários
  @Get(':id')
  @ApiOperation({ summary: 'Exibir os dados de um usuário pelo ID' })
  @Role(UserRole.ADMIN)
  async findUserById(@Param('id') id): Promise<ReturnUserDto> {
    const user = await this.usersService.findUserById(id);
    return {
      user,
      message: 'Usuário encontrado',
    };
  }

  // Endpoint de atualizar de usuários
  @Patch(':id')
  @ApiOperation({ summary: 'Atualizar os dados de um usuário por ID' })
  async updateUser(
    @Body(ValidationPipe) updateUserDto: UpdateUserDto,
    @GetUser() user: User,
    @Param('id') id: string,
  ) {
    if (user.role != UserRole.ADMIN && user.id.toString() != id) {
      throw new ForbiddenException(
        'Você não tem autorização para acessar esse recurso',
      );
    } else {
      return this.usersService.updateUser(updateUserDto, id);
    }
  }

  // Endpoint de deleção
  @Delete(':id')
  @ApiOperation({ summary: 'Remover um usário' })
  @Role(UserRole.ADMIN)
  async deleteUser(@Param('id') id: string) {
    await this.usersService.deleteUser(id);
    return {
      message: 'Usuário removido com sucesso',
    };
  }

  // Endpoint de pesquisar
  @Get()
  @ApiOperation({ summary: 'Pesquisar usuários' })
  @Role(UserRole.ADMIN)
  async findUsers(@Query() query: FindUsersQueryDto) {
    const found = await this.usersService.findUsers(query);
    return {
      found,
      message: 'Usuários encontrados',
    };
  }
}
