package com.yyj.security.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;

/**
 * MyBatis配置类
 * Created by macro on 2019/4/8.
 */
@Configuration
@MapperScan({"com.yyj.security.mbg.mapper","com.yyj.security.dao"})
public class MyBatisConfig {
}
