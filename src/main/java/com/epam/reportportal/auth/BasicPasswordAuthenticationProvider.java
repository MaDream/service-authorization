/*
 * Copyright 2016 EPAM Systems
 *
 *
 * This file is part of EPAM Report Portal.
 * https://github.com/reportportal/service-authorization
 *
 * Report Portal is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Report Portal is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Report Portal.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.epam.reportportal.auth;

import com.atlassian.crowd.embedded.api.PasswordCredential;
import com.atlassian.crowd.integration.rest.service.factory.RestCrowdClientFactory;
import com.atlassian.crowd.model.authentication.Session;
import com.atlassian.crowd.model.authentication.UserAuthenticationContext;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.model.user.UserWithAttributes;
import com.atlassian.crowd.service.client.CrowdClient;
import com.epam.reportportal.auth.event.UiAuthenticationFailureEventHandler;
import com.epam.reportportal.auth.event.UiUserSignedInEvent;
import com.epam.ta.reportportal.commons.validation.BusinessRule;
import com.epam.ta.reportportal.ws.model.ErrorType;
import com.epam.ta.reportportal.ws.model.user.CreateUserRQFull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.inject.Provider;
import javax.servlet.http.HttpServletRequest;
import java.util.Collections;

/**
 * Checks whether client have more auth errors than defined and throws exception if so
 *
 * @author <a href="mailto:andrei_varabyeu@epam.com">Andrei Varabyeu</a>
 */
class BasicPasswordAuthenticationProvider extends DaoAuthenticationProvider {

	@Autowired
	private ApplicationEventPublisher eventPublisher;

	@Autowired
	private UiAuthenticationFailureEventHandler failureEventHandler;

	@Autowired
	private Provider<HttpServletRequest> request;

	@Autowired
	private ApiRestConsumer apiRestConsumer;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		boolean accountNonLocked = !failureEventHandler.isBlocked(request.get());
		System.out.println("---------------- " + "in authenticate method".toUpperCase() + " ----------------");
		String username = authentication.getPrincipal().toString();

		if (username.equals("superadmin")) {
			System.out.println("---------------- superadmin IS ABOUT TO LOGIN!!! ----------------");
			Authentication auth = super.authenticate(authentication);
			eventPublisher.publishEvent(new UiUserSignedInEvent(auth));
			return auth;
		}

		String credentials = authentication.getCredentials().toString();
		CrowdClient client = new RestCrowdClientFactory().newInstance("http://localhost:8095/crowd",
				"reportportal",
				"qwerty");
		PasswordCredential passwordCredential = new PasswordCredential(credentials);
		UserAuthenticationContext userAuthenticationContext = new UserAuthenticationContext(
				username, passwordCredential, new ValidationFactor[]{}, "reportportal");
		try {
			System.out.println("---------------- CROWD SESSION CREATION... ----------------");
			System.out.println();
			Session session = client.validateSSOAuthenticationAndGetSession(
					client.authenticateSSOUser(userAuthenticationContext),
					Collections.emptyList());
			System.out.println("CROWD SESSION TOKEN:" + session.getToken());
			UserWithAttributes crowdUser = client.getUserWithAttributes(username);
			if (crowdUser.getExternalId() != null &&
					!crowdUser.getExternalId().equals("")) {
				try {
					System.out.println("---------------- TRYING TO FIND REPORTPORTAL USER ----------------");
					UserDetails user = super.retrieveUser(username, (UsernamePasswordAuthenticationToken)authentication);
					System.out.println("---------------- GOING TO AUTHETICATE RP USER ----------------");
					authentication = super.createSuccessAuthentication(username, authentication, user);
				} catch (UsernameNotFoundException UNF) {
					System.out.println("---------------- RP USER NOT FOUND ----------------");
					System.out.println(UNF.toString());
					System.out.println("REGISTERING NEW USER...");
					this.register(authentication, crowdUser);
				}
			}
		} catch (java.lang.Exception exc) {
			System.out.println(exc.toString());
		}

		if (!accountNonLocked) {
			BusinessRule.fail().withError(ErrorType.ADDRESS_LOCKED);
		}

		eventPublisher.publishEvent(new UiUserSignedInEvent(authentication));
		return authentication;
	}

	private void register(Authentication authentication, UserWithAttributes crowdUser) {
		CreateUserRQFull reportPortalNewUser = new CreateUserRQFull();
		reportPortalNewUser.setLogin(authentication.getPrincipal().toString());
		reportPortalNewUser.setPassword(authentication.getCredentials().toString());
		reportPortalNewUser.setFullName(crowdUser.getFirstName() + " " + crowdUser.getLastName());
		reportPortalNewUser.setEmail(crowdUser.getEmailAddress());
		reportPortalNewUser.setAccountRole("USER");
		reportPortalNewUser.setDefaultProject(reportPortalNewUser.getLogin() + "'s project");
		reportPortalNewUser.setProjectRole("PROJECT_MANAGER");
		apiRestConsumer.registerByAdmin(reportPortalNewUser);
	}
}