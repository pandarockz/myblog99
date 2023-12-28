package com.myblog9.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class MainUtil {

    private static final Logger logger = LoggerFactory.getLogger(MainUtil.class);

    public static void main(String[] args) {
        logger.debug("debug message");
        logger.info("Info message");
        logger.warn("Warning message");
        logger.error("Error message");
    }

//    public static void main(String[] args) {
//     PasswordEncoder encoder = new BCryptPasswordEncoder();
//        System.out.println(encoder.encode("Testing"));

    }

