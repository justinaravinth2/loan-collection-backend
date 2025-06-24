package com.loan.collection.service;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Service;

import com.loan.collection.dto.ChangePasswordFormDTO;
import com.loan.collection.dto.LoginFormDTO;
import com.loan.collection.dto.RefreshTokenDTO;
import com.loan.collection.dto.ResetPasswordFormDTO;
import com.loan.collection.dto.SignUpFormDTO;
import com.loan.collection.dto.UserResponseDTO;
import com.loan.collection.entity.UserVO;
import com.loan.collection.exception.ApplicationException;

@Service
public interface AuthService {

	public void signup(SignUpFormDTO signUpRequest);

	public UserResponseDTO login(LoginFormDTO loginRequest, HttpServletRequest request) throws ApplicationException;

	public void logout(String userName);

	public void changePassword(ChangePasswordFormDTO changePasswordRequest);

	public void resetPassword(ResetPasswordFormDTO resetPasswordRequest);

	public RefreshTokenDTO getRefreshToken(String userName, String tokenId) throws ApplicationException;
	
	
	
	List<UserVO>getAllUsersByOrgId(Long orgId);
	
	public UserVO getUserById(Long userId);

	public UserVO getUserByUserName(String userName);

	

}
