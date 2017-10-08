### 一、Entity  (User & Role -> 多對多關係)
1. UserEntity 要實作 UserDetails<br>
    `public class UserEntity extends GenericEntity implements SocialUserDetails`
    
   要有的屬性<br>
   會員帳號(String)、 會員密碼(String)、 是否啟用(Boolean)、 角色(RoleEntity)<br>
   
		@ManyToMany(fetch = FetchType.EAGER, cascade = {CascadeType.ALL})
		@JoinTable(name = "USER_ROLE", joinColumns = @JoinColumn(name = "USER_ID"), inverseJoinColumns = @JoinColumn(name = "ROLE_ID"))
		private Set<RoleEntity> roles; // 角色

2. override 並加上 @JsonIgnore<br>

		@JsonIgnore
		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			// return 授予的權限
			if (roles == null){
				return Lists.newArrayList();
			}
			return roles;  
		}

		@JsonIgnore
		@Override
		public String getUsername() {
			return null;   // 放你的 UserName
		}

		@JsonIgnore
		@Override
		public boolean isAccountNonExpired() {
			return true; // 帳戶是否過期
		}
	
   	        @JsonIgnore
		@Override
		public boolean isAccountNonLocked() {
			return true;
		}

		@JsonIgnore
		@Override
		public boolean isCredentialsNonExpired() {
			return true;   // 密碼是否過期
		}

		@Override
		public boolean isEnabled() {
			return enabled;  // 該會員是否啟用
		}

3. RoleEntity 實作 GrantedAuthority

	`public class RoleEntity extends GenericEntity implements GrantedAuthority`

    要有的屬性
    角色名稱(String)、角色代碼(String)、會員(UserEntity)
    
		@ManyToMany(mappedBy="roles") 
                private Set<UserEntity> users; // 會員


4.  override 並加上 @JsonIgnore

		@JsonIgnore
		@Override
		public String getAuthority() {
			return code;  // 角色代碼
		}
    
5. 避免循環呼叫

	在class上加上
	`@JsonIdentityInfo(generator=ObjectIdGenerators.IntSequenceGenerator.class, property="@id")`
    
    toString裡面也不要有會有重複呼叫的物件

		@Override
		public String toString() {
		return "RoleEntity [name=" + name + ", code=" + code +"]";
		}

### 二、 實作 UserDetailsService

1. 新建一個class，實作UserDetailsSerivce

		@Service
		public class UserDetailsServiceImpl implements UserDetailsService{

		@Autowired
		private UserDao userDao;
	
		@Override
		public UserDetails loadUserByUsername(String accountNumber) throws UsernameNotFoundException {
		
			final UserEntity user = userDao.findByAccountNumber(accountNumber);
			if (user == null) {
				throw new UsernameNotFoundException(accountNumber);
			}
			return user;
			}

		}

### 三、 Config ，在這邊是使用 WebSecurityConfig

1. 繼承 WebSecurityConfigurerAdapter

		@Configuration
		@EnableWebSecurity
		public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

2. Autowired UserDetailsService

	    @Autowired
	    private UserDetailsService userDetailsService;
    
3. override configure
   
    	@Override
    	protected void configure(HttpSecurity http) throws Exception {
		
		// 後台 會員管理設定: ADMIN, SERVICE
                // 可以連結到 /admin/user的人，只有有 ADMIN、 SERVICE 這兩個權限的人
		http.authorizeRequests().antMatchers("/admin/user/**")
		.hasAnyRole("ADMIN", "SERVICE")
		.and().formLogin().loginPage("/login").permitAll();
		
		// 整個後台
		http.authorizeRequests().antMatchers("/admin/**")
		.hasAnyRole("ADMIN")
		.and().formLogin().loginPage("/login").permitAll();
		
        http.authenticationProvider(daoAuthenticationProvider())
        	.authorizeRequests()
        	.antMatchers(
                		"/", 
                		"/resources/**",
                		"/userfiles/**",
                		"/insurer/**", 
                		"/product/**", 
                		"/article/**",
                		"/jolokia/**",
                		"/registered/**",
                		"/signin/**",
                		"/signup/**"
                		).permitAll().anyRequest().authenticated()
            .and().headers().frameOptions().sameOrigin()
            .and().formLogin().loginPage("/login").permitAll()
            .and().logout().permitAll();
        
   	     }
     
     	@Bean
        public DaoAuthenticationProvider daoAuthenticationProvider() {
		// 抓到DB的user，使其可以進行登入
		final DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
                                            
		provider.setUserDetailsService(userDetailsService);
		
		provider.setPasswordEncoder(passwordEncoder());
		return provider;
		}
        
        @Bean
		public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();  // 密碼加密
		}
        
	    @Autowired
  	    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
            // 為特定的使用者綁定相對應的Role​​​
            // 可以用 帳號 user 密碼 user1234 登入並擁有 USER 角色權限
            // 可以用 帳號 admin 密碼 admin1234 登入並擁有 ADMIN 角色權限
    	    auth.inMemoryAuthentication()
        	.withUser("user").password("user1234").roles("USER")
        	.and().withUser("admin").password("admin1234").roles("ADMIN");
  	    }

### 四、 JSP

1. 加tag

	`<%@ taglib prefix="sec"
	uri="http://www.springframework.org/security/tags"%>`

2. 用 section 把 輸入帳號密碼的 form 包起來

	`<section class="login-form"> </section>`
    
3.  form 的處理

		<form method="post" action="${pageContext.request.contextPath}/login"  role="login" name="normalForm" id="normalForm">
		<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />

4. 再加入畫面需要的輸入帳號密碼欄位

		<div class="col-sm-12" style="margin: 16px">
			<input type="text" name="username"
				placeholder="請輸入您註冊時的 e-mail" 
				required class="form-control input-md" />
		</div>

		<div class="col-sm-12" style="margin: 16px">
			<input type="password" name="password" placeholder="密碼"
				required class="form-control input-md" />
		</div>
        
### 五、 導覽列 JSP

1. 加入 sec tag 後，可以使用下列來決定甚麼權限的人可以在前端看到哪一頁 <br>
	`<sec:authorize access="hasAnyRole('ADMIN','SERVICE')">` <br>
   注意: 這只是在前端導覽列控制，沒有 XX權限的人若有連到XX頁面的網址還是能夠進入該頁。(可參考本章3.3做修改)<br>
   
2. 導覽列上的登出、登入，用 sec 控制

    登入

		<sec:authorize access="hasRole('ROLE_ANONYMOUS')">
   	    	    <li><a href="/login" style="color: white">登入</a></li>
   		</sec:authorize>
    
    登出

    	   <sec:authorize access="!hasRole('ROLE_ANONYMOUS')">
     
			<li><a href="#" onclick="$('#logout').submit();" 
            			style="color: white">
                		<span class="glyphicon glyphicon-log-out" style="color: white">
                                </span>登出</a>
            	         </li>
                
			<form class="hide" id="logout" 
            		action="<c:url value="/logout" />"
					method="post">
				<input type="hidden" name="${_csrf.parameterName}"
					value="${_csrf.token}" />
			</form>
	    </sec:authorize>

### 六、 PasswordEncoder

1. 要使用PasswordEncoder 需在要使用的Service 加上

	`@Autowired private PasswordEncoder passwordEncoder;`
    
2. 寫一個 method 在呼叫他

 		public String encodePasswrod(final String rawPassword) {
			if (!StringUtils.isBlank(rawPassword)){
				return passwordEncoder.encode(rawPassword);
			} else {
				return null;
			}
		}    
        
3. 因為不能解碼，所以若要比對兩個加密密碼是否相同，需要使用 matches

		if(!passwordEncoder.matches(entity.getOrgPassword(), dbEntity.getPassword())){
			messages.add(Message.builder().code("orgPassword").value("與原始密碼不符").build());
		}
    
### 七、 其他補充: Role 權限更改

1. 避免更新時，該使用者的角色有異常

		@Transactional
		@Override
		public UserEntity handleUpdate(final UserEntity entity) {
        
			// 傳進來前Controller要先撈到entity的所有資料，以免資料更新異常
			final UserEntity dbUserEntity = userDao.findOne(entity.getId());	
			dbUserEntity.getRoles().clear();
			for (final RoleEntity role : entity.getRoles()) {
				final RoleEntity dbRoleEntity = roleDao.getOne(role.getId());
				dbUserEntity.getRoles().add(dbRoleEntity);
			}
			return dbUserEntity;
		}
        
2. 修正權限 畫面 JSP
	用多選呈現
        ![](https://github.com/hildachang/TEST2/blob/master/temp/spring%20security/pic/role_multiSelected.PNG?raw=true)

		<table name="roles">
			<tr>
				<td>
					<div class="panel panel-info">
						<div class="panel-heading text-center"><strong>未選擇</strong></div>
						<select multiple id="unselectedRoles" name="unselectedRoles" 
								style="height:200px; width:350px" class="form-control">
								
							<c:forEach items="${unselectedRoles}" var="role">
								<option value="${role.id}">${role.name} (${role.code}) </option>
							</c:forEach>
							
						</select>
					</div>
				</td>
				
				<td class="col-md-1">
				
					<button type="button" class="btn btn-info" id="rolesAddBtn">
						<span class="glyphicon glyphicon-chevron-right"/>
					</button></br></br>
					
					<button type="button" class="btn btn-info" id="rolesRemoveBtn">
						<span class="glyphicon glyphicon-chevron-left"/>
					</button>
					
				</td>
				
				<td>
					<div class="panel panel-info">
						<div class="panel-heading text-center"><strong>已選擇</strong></div>											
						<select multiple id="selectedRoles" name="roles[].id" 
								style="height:200px; width:350px" class="form-control" data-content-type="array">
								
							<c:forEach items="${selectedRoles}" var="role">
								<option value="${role.id}">${role.name} (${role.code})</option>
							</c:forEach>	
							
						</select>
					</div>
				</td>
			</tr>
		</table>   


### 參考網址
[Spring Secutriy](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/) 

[Spring Secutriy JSP標籤](http://elim.iteye.com/blog/2263097)

#### 搭配 Spring Security 參考
UserDetailsService  -> 需要實作 (註冊) <br>
configure  (HttpSecurity，確保只能用form之類的方法連近來)<br>
SpringAuthenticationProvider   (驗證登入成功或失敗)<br>
BCryptPasswordEncoder passwordEncoder  (密碼不能存明碼)<br>
csrf (建立token，避免攻擊, 18.4.3  logout也要寫)<br>
web 需註冊filter 並對所有攔截  (6.2.1  web.xml Configuration)<br>
authentication 做登入驗證 (6.2.5)<br>
tablib (30)<br>
principal 得到角色<br>