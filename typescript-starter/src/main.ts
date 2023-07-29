import { HttpAdapterHost, NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe,ClassSerializerInterceptor } from '@nestjs/common';
import { ExceptionsLoggerFilter } from './utils/exceptionLogger.exception';
import { ExcludeNullInterceptor } from './utils/excludeNullInterceptors';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const { httpAdapter } = app.get(HttpAdapterHost);
  app.useGlobalPipes(new ValidationPipe({
    transform: true,
    transformOptions: {
      enableImplicitConversion: false,
    },
  }));
  app.useGlobalFilters(new ExceptionsLoggerFilter(httpAdapter));

  app.useGlobalInterceptors(new ExcludeNullInterceptor())
  app.useGlobalInterceptors(new ClassSerializerInterceptor(
    app.get(Reflector))
  );

  app.use(cookieParser());
  await app.listen(3001, "0.0.0.0");
}
bootstrap();
