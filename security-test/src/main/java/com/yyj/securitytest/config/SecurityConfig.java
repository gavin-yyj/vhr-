package com.yyj.securitytest.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.org.apache.xpath.internal.operations.And;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import sun.security.util.Password;

import javax.sql.DataSource;
import java.io.PrintWriter;

/**
 * security-test
 *
 * @author 小杰哥
 * @date 2020/05/11
 */
@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * 实现角色继承
     * @return
     */
    @Bean
    RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return hierarchy;
    }

    @Autowired
    DataSource dataSource;
    @Override
    @Bean
    protected UserDetailsService userDetailsService(){
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        JdbcUserDetailsManager manager = new JdbcUserDetailsManager(dataSource);
        if(!manager.userExists("yyj")){
            manager.createUser(User.withUsername("yyj").password("123456").roles("admin").build());
        }
        if(!manager.userExists("田力")){
            manager.createUser(User.withUsername("田力").password("123").roles("user").build());
        }
        if(!manager.userExists("杨玉杰")){
            manager.createUser(User.withUsername("杨玉杰").password("123").roles("admin").build());
        }
        return manager;
    }
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        /**
//         * 通过 inMemoryAuthentication 来开启在内存中定义用户，withUser 中是用户名，password 中则是用户密码，
//         * roles 中是用户角色。如果需要配置多个用户，用 and 相连。
//         */
//        auth.inMemoryAuthentication()
//                .withUser("yyj")
//                .password("123456")
//                .roles("admin")
//                .and()
//                .withUser("田力")
//                .password("123")
//                .roles("user");
//    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        /**
         * 用来配置忽略掉的URL地址，主要是针对静态文件
         */
        web.ignoring().antMatchers("/js/**","/css/**","/images/**");
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * 所有的请求都需要认证
         * permitALL：登录相关的页面/接口不要被拦截
         * 关闭csrf
         */
        http.authorizeRequests()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                .anyRequest().authenticated()
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler((req,resp,authentication)->{
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write("注销成功");
                    out.flush();
                    out.close();
                })
//                .logoutSuccessUrl("/index")
                .deleteCookies()
                .and()
                .formLogin()
                .loginPage("/login.html")
                .loginProcessingUrl("/doLogin")
                .successHandler((req,resp,authentication)->{
                    Object principal = authentication.getPrincipal();
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(new ObjectMapper().writeValueAsString(principal));
                    out.flush();
                    out.close();
                })
                .failureHandler((req,resp,e)->{
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(e.getMessage());
                    out.flush();
                    out.close();
                })
                .permitAll()
                .and()
                .csrf().disable();
//                .exceptionHandling()
//                .authenticationEntryPoint((req,resp,authException)->{
//                    resp.setContentType("application/json;charset=utf-8");
//                    PrintWriter out = resp.getWriter();
//                    out.write("尚未登陆，请先登录");
//                    out.flush();
//                    out.close();
//                });
    }
}
