import { Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { CanActivate, ExecutionContext } from '@nestjs/common';
import {
  AppAbility,
  CaslAbilityFactory,
} from '../factories/casl-ability.factory';
import { PolicyHandler } from '../interfaces/policy-handler.interface';
import { CHECK_POLICIES_KEY } from '../decorators/metadata/check-policy.decorator';
import { User } from 'src/entities/user.entity';
import { Request } from 'express';

/**
 * @class PoliciesGuard
 * @implements CanActivate
 * @description
 * 权限策略守卫，用于在路由处理前根据定义的权限策略（PolicyHandler）动态校验当前用户是否有权访问目标资源。
 *
 * 代码原理与机制说明：
 * 1. 该守卫通过依赖注入Reflector和CaslAbilityFactory，结合CASL能力系统，实现细粒度的权限控制。
 * 2. canActivate方法会在每次路由请求前被调用，首先通过Reflector获取当前路由上定义的所有PolicyHandler（权限策略处理器）。
 *    - 这些PolicyHandler通过@CheckPolicies装饰器声明在路由或控制器上，支持函数或类实现。
 * 3. 随后从HTTP请求对象中提取当前用户信息（user），并通过CaslAbilityFactory为该用户生成CASL能力对象（AppAbility）。
 * 4. 遍历所有PolicyHandler，依次调用execPolicyHandler方法，传入能力对象、用户信息和请求对象，判断每个策略是否通过。
 *    - 若所有策略均返回true，则允许访问；只要有一个策略不通过，则拒绝访问。
 * 5. execPolicyHandler方法兼容函数式和类式的PolicyHandler，自动区分并调用对应的校验逻辑。
 *
 * 该守卫实现了灵活、可扩展的权限校验机制，支持多策略组合，适用于复杂的业务权限场景。
 */
@Injectable()
export class PoliciesGuard implements CanActivate {
  /**
   * @constructor
   * @param reflector 反射工具，用于获取路由元数据
   * @param caslAbilityFactory CASL能力工厂，用于生成用户能力对象
   */
  constructor(
    private reflector: Reflector,
    private caslAbilityFactory: CaslAbilityFactory,
  ) {}

  /**
   * @method canActivate
   * @description
   * 路由守卫主方法，判断当前请求是否有权限访问目标资源。
   *
   * @param context 当前执行上下文，包含请求、路由等信息
   * @returns Promise<boolean> 是否允许访问
   */
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 获取当前路由上定义的所有权限策略处理器（PolicyHandler）
    const policyHandlers =
      this.reflector.get<PolicyHandler[]>(
        CHECK_POLICIES_KEY,
        context.getHandler(),
      ) || [];

    // 从请求对象中提取当前用户信息
    const { user } = context.switchToHttp().getRequest();
    // 为当前用户生成CASL能力对象
    const ability = this.caslAbilityFactory.createForUser(user);

    // 依次执行所有策略处理器，全部通过才允许访问
    return policyHandlers.every((handler) =>
      this.execPolicyHandler(
        handler,
        ability,
        user,
        context.switchToHttp().getRequest(),
      ),
    );
  }

  /**
   * @method execPolicyHandler
   * @description
   * 执行单个权限策略处理器，判断是否通过权限校验。
   *
   * 原理与机制：
   * - 支持函数式和类式两种PolicyHandler实现方式。
   * - 函数式直接调用，类式调用其handle方法。
   *
   * @param handler 权限策略处理器（函数或类）
   * @param ability 当前用户的CASL能力对象
   * @param user 当前用户信息
   * @param request 当前请求对象
   * @returns boolean 是否通过该策略校验
   */
  private execPolicyHandler(
    handler: PolicyHandler,
    ability: AppAbility,
    user: User,
    request: Request,
  ) {
    if (typeof handler === 'function') {
      // 函数式策略处理器
      return handler(ability, user, request);
    }
    // 类式策略处理器
    return handler.handle(ability, user, request);
  }
}
