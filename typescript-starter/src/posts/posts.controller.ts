import { Body, Controller, Delete, Get, Param, Post, Put, UseFilters, UseGuards } from '@nestjs/common';
import PostsService from './posts.service';
import {CreatePostDto} from './dto/createPost.dto';
import {UpdatePostDto} from './dto/updatePost.dto';
import JwtAuthenticationGuard from 'src/authentication/jwt-authentication.guard';
import { ExceptionsLoggerFilter } from 'src/utils/exceptionLogger.exception';
import { FindOneParams } from 'src/utils/findOneParams.exception';
 
@Controller('posts')
export default class PostsController {
  constructor(
    private readonly postsService: PostsService
  ) {}
 
  @Get()
  getAllPosts() {
    return this.postsService.getAllPosts();
  }
 
  @Get(':id')
  @UseFilters(ExceptionsLoggerFilter)
  getPostById(@Param() {id}: FindOneParams) {
    return this.postsService.getPostById(Number(id));
  }
  
  @UseGuards(JwtAuthenticationGuard)
  @Post()
  async createPost(@Body() post: CreatePostDto) {
    return this.postsService.createPost(post);
  }
 
  @Put(':id')
  async replacePost(@Param('id') id: string, @Body() post: UpdatePostDto) {
    return this.postsService.updatePost(Number(id), post);
  }
 
  @Delete(':id')
  async deletePost(@Param('id') id: string) {
    this.postsService.deletePost(Number(id));
  }
}