package com.elearning.api.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.stereotype.Service;

@Service
public class MailClient {
	private JavaMailSender mailSender;
	@Autowired
	private MailContentBuilder mailContentBuilder;

	@Autowired
	public MailClient(JavaMailSender mailSender) {
		this.mailSender = mailSender;
	}

	public void prepareAndSend(String recipient, String message) {
		MimeMessagePreparator messagePreparator = mimeMessage -> {
			MimeMessageHelper messageHelper = new MimeMessageHelper(mimeMessage);
			String content = mailContentBuilder.build(message);
	        messageHelper.setText(content, true);
			messageHelper.setFrom("aaroor2015@gmail.com");
			messageHelper.setTo(recipient);
			messageHelper.setSubject("Sample mail subject");
			messageHelper.setText(content,true);
		};
		try {
			mailSender.send(messagePreparator);
		} catch (MailException e) {
			// runtime exception; compiler will not force you to handle it
		}
	}
}
