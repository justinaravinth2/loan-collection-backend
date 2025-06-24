package com.loan.collection.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.loan.collection.entity.TokenVO;

@Repository
public interface TokenRepo extends JpaRepository<TokenVO, String>{

}
