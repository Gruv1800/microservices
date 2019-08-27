package example.local.authenticationserver.configuration;

import example.local.authenticationserver.model.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpointAuthenticationFilter;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import javax.sql.DataSource;
import java.util.Map;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Value("${check-user-scopes}")
    private boolean checkUserScope;
    private final DataSource dataSource;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final ClientDetailsService clientDetailsService;

    private JwtAccessTokenConverter jwtAccessTokenConverter;
    private TokenEndpointAuthenticationFilter tokenEndpointAuthenticationFilter;
    private TokenStore tokenStore;
    private CustomOauth2RequestFactory oAuth2RequestFactory;

    public AuthorizationServerConfiguration(final DataSource dataSource, final PasswordEncoder passwordEncoder,
                                            final AuthenticationManager authenticationManager,
                                            final UserDetailsService userDetailsService,
                                            final ClientDetailsService clientDetailsService) {
        this.dataSource = dataSource;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.clientDetailsService = clientDetailsService;
    }

    @Bean
    public TokenStore tokenStore() {
        if (this.tokenStore == null) {
            this.tokenStore = new JdbcTokenStore(dataSource);
        }
        return this.tokenStore;
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        if (jwtAccessTokenConverter == null) {
            jwtAccessTokenConverter = new CustomTokenEnhancer();
            jwtAccessTokenConverter.setSigningKey("password");
        }
        return jwtAccessTokenConverter;
    }

    @Bean
    public TokenEndpointAuthenticationFilter tokenEndpointAuthenticationFilter() {
        if (tokenEndpointAuthenticationFilter == null) {
            tokenEndpointAuthenticationFilter = new TokenEndpointAuthenticationFilter(authenticationManager, requestFactory());
        }
        return this.tokenEndpointAuthenticationFilter;
    }

    @Bean
    public OAuth2RequestFactory requestFactory() {
        if (oAuth2RequestFactory == null) {
            oAuth2RequestFactory = new CustomOauth2RequestFactory(clientDetailsService, tokenStore);
            oAuth2RequestFactory.setCheckUserScopes(true);
        }
        return oAuth2RequestFactory;
    }

    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer.passwordEncoder(this.passwordEncoder)
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {
        clients.jdbc(this.dataSource).passwordEncoder(this.passwordEncoder);
    }

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints.tokenStore(tokenStore()).tokenEnhancer(jwtAccessTokenConverter())
                .authenticationManager(authenticationManager).userDetailsService(userDetailsService);
        if (checkUserScope) {
            endpoints.requestFactory(requestFactory());
        }
    }

   final class CustomOauth2RequestFactory extends DefaultOAuth2RequestFactory {

        private final TokenStore tokenStore;

        public CustomOauth2RequestFactory(ClientDetailsService clientDetailsService, TokenStore tokenStore) {
            super(clientDetailsService);
            this.tokenStore = tokenStore;
        }

        @Override
        public TokenRequest createTokenRequest(Map<String, String> requestParameters, ClientDetails authenticatedClient) {
            if (requestParameters.get("request_type").equals("refresh_token")) {
                OAuth2Authentication oAuth2Authentication = tokenStore.readAuthenticationForRefreshToken(
                        tokenStore.readRefreshToken(requestParameters.get("refresh_token"))
                );
                SecurityContextHolder.getContext()
                        .setAuthentication(new UsernamePasswordAuthenticationToken(
                                oAuth2Authentication.getName(),
                                null,
                                userDetailsService.loadUserByUsername(oAuth2Authentication.getName()).getAuthorities())
                        );
            }
            return super.createTokenRequest(requestParameters, authenticatedClient);
        }
    }

    final class CustomTokenEnhancer extends JwtAccessTokenConverter {
        @Override
        public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
            User user = (User) authentication.getPrincipal();
            Map<String, Object> info = accessToken.getAdditionalInformation();
            info.put("email", user.getEmail());
            DefaultOAuth2AccessToken customAccessToken = new DefaultOAuth2AccessToken(accessToken);
            customAccessToken.setAdditionalInformation(info);
            return super.enhance(customAccessToken, authentication);
        }
    }
}
