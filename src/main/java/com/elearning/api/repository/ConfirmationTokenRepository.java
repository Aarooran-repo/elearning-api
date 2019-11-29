package com.elearning.api.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.elearning.api.model.ConfirmationToken;

public interface ConfirmationTokenRepository extends JpaRepository<ConfirmationToken, Long> {

	ConfirmationToken findByConfirmationToken(String confirmationToken);

}
