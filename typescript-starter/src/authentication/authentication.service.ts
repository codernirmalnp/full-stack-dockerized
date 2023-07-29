import * as  bcrypt from 'bcrypt'
import {Response} from 'express'
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { UserService } from "../user/user.service";
import { RegisterDto } from "./dto/RegisterDto.dto";

import { TokenPayload } from './tokenPayload.interface';
import { PostgresErrorCode } from 'src/database/postgresErrorCodes.enum';



@Injectable()
export class AuthenticationService {
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService
    ) { }
    public async register(registrationData: RegisterDto) {
        const hashedPassword = await bcrypt.hash(registrationData.password, 10);

        try {
            const createdUser = await this.userService.create({
                ...registrationData,
                password: hashedPassword
            });
        
         
           
            return createdUser
            
        } catch (error) {
            if (error?.code === PostgresErrorCode.UniqueViolation) {
                throw new HttpException('User with that email already exists', HttpStatus.BAD_REQUEST);
            }
            throw new HttpException('Something Went wrong', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public async getAuthenticatedUser(email: string, plainTextPassword: string) {
        try {
            const user = await this.userService.getByEmail(email);
            await this.verifyPassword(plainTextPassword, user.password);
       
            return user;
        } catch (error) {
            throw new HttpException('Wrong credentials provided', HttpStatus.BAD_REQUEST);
        }
    }


    private async verifyPassword(plainTextPassword: string, hashedPassword: string) {
        const isPasswordMatching = await bcrypt.compare(
            plainTextPassword,
            hashedPassword
        );
        if (!isPasswordMatching) {
            throw new HttpException('Wrong credentials provided', HttpStatus.BAD_REQUEST);
        }
    }

    public getCookieWithJwtToken(userId: number) {
        const payload: TokenPayload = { userId };
        const token = this.jwtService.sign(payload);
        return `Authentication=${token}; HttpOnly; Path=/; Max-Age=${this.configService.get('JWT_EXPIRATION_TIME')}`;
    }

    public getCookieForLogOut() {
        return `Authentication=; HttpOnly; Path=/; Max-Age=0`;
      }

}