package com.alibou.security.token;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Integer> {


    // select t from Token t and then i will inner join it then i need to add my condition
    // this is the query t.user.id = u.id
    // then add condition, that token belongs to that selected user
    // where clause where u.id equals userId the one I have as parameter in findAllValidTokensByUser(Integer userId);
    // and now i want all the valid token means not expired and not revoked
    //
    @Query("""
            select t from Token t inner join User u on t.user.id = u.id
            where u.id = :userId and (t.expired = false or t.revoked = false)
            """)
    List<Token> findAllValidTokensByUser(Integer userId);


    Optional<Token> findByToken(String token);

}
