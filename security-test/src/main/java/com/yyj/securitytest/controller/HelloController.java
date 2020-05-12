package com.yyj.securitytest.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * security-test
 *
 * @author 小杰哥
 * @date 2020/05/11
 *
 * 测试
 */
@RestController
public class HelloController {
    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    @GetMapping("/admin/hello")
    public String admin(){
        return "admin";
    }

    @GetMapping("/user/hello")
    public String user(){
        return "user";
    }
}
