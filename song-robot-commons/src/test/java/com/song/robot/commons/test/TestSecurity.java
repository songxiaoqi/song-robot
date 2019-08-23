package com.song.robot.commons.test;

import com.song.robot.commons.utils.SecurityUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.NoSuchAlgorithmException;

/**
 * 加密测试
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class TestSecurity {

    @Test
    public void testSecurity() {
        try {
            System.out.println(String.format("%s加密结果:%s",SecurityUtils.MD5,SecurityUtils.encrypt(SecurityUtils.MD5,"hello".getBytes())));
            System.out.println(String.format("%s加密结果:%s",SecurityUtils.SHA1,SecurityUtils.encrypt(SecurityUtils.SHA1,"hello".getBytes())));
            System.out.println(String.format("%s加密结果:%s",SecurityUtils.SHA256,SecurityUtils.encrypt(SecurityUtils.SHA256,"hello".getBytes())));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}
