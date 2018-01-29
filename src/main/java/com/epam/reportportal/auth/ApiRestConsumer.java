package com.epam.reportportal.auth;

import com.epam.ta.reportportal.exception.ReportPortalException;
import com.epam.ta.reportportal.ws.model.user.CreateUserRQFull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;

@Service
public class ApiRestConsumer {

    @Value("${crowd.bearer}")
    private String superAdminToken;

    void registerByAdmin(CreateUserRQFull createUserRQFull) {
        try {
            RestTemplate restTemplate = new RestTemplate();
            HashMap<String, String> uriParams = new HashMap<>();
            uriParams.put("HEADER", "Authorization: bearer " + superAdminToken);
            Object o = restTemplate.postForObject("http://selgrid2:api/user", createUserRQFull, Object.class, uriParams);
        } catch(Exception e) {
            throw new ReportPortalException(e.getMessage());
        }
    }
}
