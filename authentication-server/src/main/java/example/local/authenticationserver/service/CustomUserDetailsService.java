package example.local.authenticationserver.service;

import example.local.authenticationserver.model.User;
import example.local.authenticationserver.repository.UserRepository;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service(value = "userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String str) throws UsernameNotFoundException {
        Optional<User> user = Optional.empty();
        if (str.contains("@")) {
            user =userRepository.findByEmail(str);
        } else {
            userRepository.findByUsername(str);
        }
        if (!user.isPresent()) {
            throw new BadCredentialsException("Bad credentials. User " + str + " not found.");
        }
        new AccountStatusUserDetailsChecker().check(user.get());
        return user.get();
    }
}
