import { Body, Req,Res, Controller, HttpCode, Post, UseGuards ,Get,} from '@nestjs/common';
import {Response} from 'express'
import { AuthenticationService } from './authentication.service';
import RegisterDto from './dto/RegisterDto.dto';
import RequestWithUser from './registerWithUser.interface';
import { LocalAuthenticationGuard } from './localAuthentication.guard';
import JwtAuthenticationGuard from './jwt-authentication.guard';
import { ExcludeNullInterceptor } from 'src/utils/excludeNullInterceptors';




@Controller('authentication')
export class AuthenticationController {
    constructor(
        private readonly authenticationService: AuthenticationService
    ) { }

    
    @UseGuards(JwtAuthenticationGuard)
    @Get()
    authenticate(@Req() request: RequestWithUser) {
      const user = request.user;
      return user;
    }

   
    @Post('register')
    async register(@Body() registrationData: RegisterDto) { 
      const user= this.authenticationService.register(registrationData);  
      return user;
    }

    @HttpCode(200)
    @UseGuards(LocalAuthenticationGuard)
    @Post('log-in')
    async logIn(@Req() request: RequestWithUser) {
        const {user} = request;
        const cookie = this.authenticationService.getCookieWithJwtToken(user.id);
        request.res.setHeader('Set-Cookie', cookie);
        return user;
    }

    @UseGuards(JwtAuthenticationGuard)
    @Post('log-out')
    async logOut(@Req() request: RequestWithUser, @Res() response: Response) {
      response.setHeader('Set-Cookie', this.authenticationService.getCookieForLogOut());
      return response.sendStatus(200);
    }
}