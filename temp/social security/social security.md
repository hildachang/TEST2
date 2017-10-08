### 一、pom.xml
1. 增加 FB

		<!-- FB -->
		<dependency>
			<groupId>org.springframework.social</groupId>
			<artifactId>spring-social-facebook</artifactId>
		</dependency>

2. 增加 social security

		<!-- social security -->
		<dependency>
			<groupId>org.springframework.social</groupId>
			<artifactId>spring-social-security</artifactId>
		</dependency>

### 二、連到 FB
1. 新建 class 實作 SocialConfigurer 

		@EnableSocial
		@Configuration
		public class SocialConfiguration implements SocialConfigurer{

2. Autowired DataSource 和 你的 UserSerivce

		@Autowired
		private DataSource dataSource;
		
		@Autowired
		private AdminUserService adminUserService;
        
3. Override

		@Override
		public void addConnectionFactories(ConnectionFactoryConfigurer cfConfig, Environment env) {
			// 連結至FB、設置在properties檔
			//cfConfig.addConnectionFactory(new FacebookConnectionFactory("697474003783661","71a699c151bdb40341bfcebb0758510e"));
		}
	
		@Override
		public UserIdSource getUserIdSource() {
			// 找到FB的UserId那個人，pom要有spring-social-security
			return new AuthenticationNameUserIdSource();  
		}
	
		@Override
		public UsersConnectionRepository getUsersConnectionRepository(ConnectionFactoryLocator connectionFactoryLocator) {
			// 使用dataSource連結DB、建立Facebook Table
			JdbcUsersConnectionRepository repository = new JdbcUsersConnectionRepository(
					dataSource,
					connectionFactoryLocator,
					Encryptors.noOpText()
				);
			repository.setConnectionSignUp(connectionSignUp());
			repository.setTable'Prefix'("FB"); // 預設DB名稱為UserConnection，若Table名字有改，則要加 Prefix
			return repository;
		}
	
		public ConnectionSignUp connectionSignUp() {
			//第一次FB進來時的處理
			return new ConnectionSignUp() {
				@Override
				public String execute(Connection<?> connection) {
					UserEntity entity = new UserEntity(connection); 
					
					final Facebook api = (Facebook) connection.getApi();
					String [] fields = { "id", "email", "first_name", "gender", "last_name" };
					User userProfile = api.fetchObject("me", User.class, fields);
					
					//entity.setAccountNumber(userProfile.getEmail()); // 不能用 用email 做accounNumber，有些人的email抓不到
					entity.setName(userProfile.getLastName() + userProfile.getFirstName());
					entity.setEmail(userProfile.getEmail());
					entity.setGender(userProfile.getGender());
					log.debug("userProfile.getEmail {}", userProfile.getEmail());
					adminUserService.insert(entity);
					log.info("New social user signin: {} - {}", entity.getName(), entity.getAccountNumber());
					return connection.getKey().getProviderUserId();
				}
			};
		};
        
4. 若不在 addConnectionFactories 寫上 FB 的 appId 或 appSecret，可寫在 properties 裡面

		spring.social.facebook.appId= 你的 appId
		spring.social.facebook.appSecret= 你的 appSecret

### 三、Entity

1. SocialUserDetails 中有 UserDetail 因此 UserEntity改為實作 SocialUserDetails

		public class UserEntity extends GenericEntity implements SocialUserDetails {
        
2. 增加屬性

		@Column(name = "PROVIDER")
		private String provider; // 通路 (有需要再加)
		
		@Column(name = "PROVIDER_USER_ID")
		private String providerUserId; // social login 使用者
        
3. override

		@Override
		public String getUserId() {
			return providerUserId;
		}   
        
4. 客製從FB抓到的資料變成User資料的資訊

		public UserEntity() {
		}
	
		public UserEntity(Connection<?> connection) {
			this.provider = "FB";
			this.providerUserId = connection.getKey().getProviderUserId();
			this.accountNumber = connection.getKey().getProviderUserId();
			//this.displayName = connection.getDisplayName();
			this.name = connection.getDisplayName();
			this.enabled = true;
		}  
        
### 四、Config, 回到WebSecurityConfig
1. 加上 spring social 登入

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// spring social 登入
			springSocialConfigurer(http);  
			
			// 一般登入
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
        
2. 加上登入失敗畫面

		private void springSocialConfigurer(HttpSecurity http) throws Exception {
			http.apply(new SpringSocialConfigurer().defaultFailureUrl("/login?error"));
		}  
        
3. 加上登入判斷

		@Bean
		public SocialUserDetailsService socialUserDetailsService() {
			return new UserDetailsSocialService();
		}
        
### 五、實作 SocialUserDetailsService
1. 新建一個 class 實作 SocialUserDetailsService

		public class UserDetailsSocialService implements SocialUserDetailsService {
        
2. override loadUserByUserId

		@Override
		public SocialUserDetails loadUserByUserId(String userId) throws UsernameNotFoundException {
			final UserEntity user = userDao.findByProviderUserId(userId);
			if (user == null) {
				throw new UsernameNotFoundException("帳號不存在");
			}
	
		if (!user.getEnabled()) {
			throw new DisabledException("此帳號已經失效");
			}
		
			return user;
		}
        
### 六、建立FBConncetion Table
注意: 預設 table 名稱為 UserConnection 若有更動 需調整 (可參考本章2.3)

		create table FBUserConnection (
			userId varchar(255) not null,
			providerId varchar(255) not null,
			providerUserId varchar(255),
			rank int not null,
			displayName varchar(255),
			profileUrl varchar(512),
			imageUrl varchar(512),
			accessToken varchar(255) not null,                    
			secret varchar(255),
			refreshToken varchar(255),
			expireTime bigint,
			primary key (userId, providerId, providerUserId));
		create unique index UserConnectionRank on FBUserConnection(userId, providerId, rank);
        
### 七、login.jsp
這個例子是將FB登入按鈕改為圖片按鈕

		<form action="<c:url value="/auth/facebook" />" method="GET"
			role="form" name="fbForm" id="fbForm">
			<div class="col-sm-12" style="margin: 16px">
				<input type="hidden" name="scope" value="public_profile,email" />
				<!-- <input type="submit" value="">-->
				<button type="button" name="submit_Btn" id="submit_Btn"
					onClick="document.fbForm.submit()"
					style="background-color: white; height: 10vh; border: 2px blue none">
					<img src="/resources/pic/registered/fb_login.png"
						width="100%">
				</button>
			</div>
		</form>


### 八、補充: 抓到當前使用者

		UserDetails details = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.debug("details: {}", details.getUsername());
        
### 九、補充: 若使用者資料有改(與抓到FB的資料相關)，立即同步方法

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		Authentication newAuthentication = new UsernamePasswordAuthenticationToken(dbUserEntity, authentication.getCredentials(), authentication.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(newAuthentication);