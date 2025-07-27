import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { useContainer } from 'class-validator';
import { Logger } from 'pino-nestjs';
import {
  FastifyAdapter,
  NestFastifyApplication,
} from '@nestjs/platform-fastify';

/**
 * @function bootstrap
 * @description
 * 启动NestJS应用的主函数。该函数负责创建应用实例、配置全局功能（如版本控制、全局校验管道、日志系统等），
 * 并监听指定端口启动服务。
 *
 * 主要原理与机制如下：
 * 1. 通过NestFactory.create创建应用实例，使用FastifyAdapter适配器，并开启日志缓冲（bufferLogs: true），
 *    这样可以在Logger初始化前缓存日志，避免日志丢失。Fastify相比Express具有更好的性能表现。
 * 2. enableVersioning方法启用API版本控制，采用URI方式（如/v1/xxx），
 *    并设置默认版本为'1'，便于API的向后兼容与演进。
 * 3. useGlobalPipes注册全局校验管道，ValidationPipe会自动对请求数据进行类型转换和校验，
 *    保证入参的正确性和安全性。
 * 4. useLogger将pino-nestjs的Logger注入为全局日志系统，提升日志性能与结构化能力。
 * 5. useContainer配置class-validator使用Nest的依赖注入容器，支持依赖注入自定义校验器，
 *    fallbackOnErrors为true时，校验器解析失败时会回退到默认容器。
 * 6. 最后通过listen方法监听环境变量PORT指定的端口（默认3000），启动HTTP服务。
 */
async function bootstrap() {
  // 创建Nest应用实例，使用Fastify适配器，并开启日志缓冲
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter(),
    { bufferLogs: true },
  );

  // 启用基于URI的API版本控制，默认版本为1
  app.enableVersioning({
    type: VersioningType.URI,
    defaultVersion: '1',
  });

  // 注册全局校验管道，自动转换和校验请求数据
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
    }),
  );

  // 设置全局日志系统为pino-nestjs的Logger
  app.useLogger(app.get(Logger));

  // 配置class-validator使用Nest依赖注入容器，支持自定义校验器注入
  useContainer(app.select(AppModule), { fallbackOnErrors: true });

  // 启动HTTP服务，监听指定端口
  await app.listen(process.env.PORT ?? 3000, '0.0.0.0');
}

// 启动应用
bootstrap();
