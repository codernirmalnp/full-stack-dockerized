import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import User from './user.entity';
import CreateUserDto from './dto/createUser.dto';

@Injectable()
export class UserService {
    constructor(
        @InjectRepository(User)
        private usersRepository: Repository<User>
    ) { }
    async getById(id: number) {
        const user = await this.usersRepository.findOne({ where: { "id": id } });
        if (user) {
            return user;
        }
        throw new HttpException('User with this id does not exist', HttpStatus.NOT_FOUND);
    }


    async getByEmail(email: string) {
        const user = await this.usersRepository.findOne({ where: { "email": email } });
        if (user) {
            return user;
        }
        throw new HttpException('User with this email does not exist', HttpStatus.NOT_FOUND);
    }

    async create(userData: CreateUserDto) {
        try {
    
           
            const newUser = await this.usersRepository.create(userData);

            await this.usersRepository.save(newUser);
          
            return newUser;
            
        }
        catch(e){
           throw e;
        }
      
    }
}