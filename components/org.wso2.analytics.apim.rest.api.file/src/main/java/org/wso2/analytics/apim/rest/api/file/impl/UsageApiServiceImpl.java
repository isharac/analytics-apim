package org.wso2.analytics.apim.rest.api.file.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.analytics.apim.file.adapter.dto.UploadedFileInfoDTO;
import org.wso2.analytics.apim.file.rest.api.util.AuthDTO;
import org.wso2.analytics.apim.rest.api.file.NotFoundException;
import org.wso2.analytics.apim.rest.api.file.UsageApiService;
import org.wso2.analytics.apim.rest.api.file.exceptions.AuthenticationException;
import org.wso2.analytics.apim.rest.api.file.util.AuthenticatorUtil;
import org.wso2.analytics.apim.rest.api.file.util.UploadServiceConstants;
import org.wso2.msf4j.Request;
import org.wso2.msf4j.formparam.FileInfo;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import java.io.InputStream;

public class UsageApiServiceImpl extends UsageApiService {
    private static final Logger log = LoggerFactory.getLogger(UsageApiServiceImpl.class);

    @Override
    public Response usageUploadFilePost(InputStream analyticsInputStream, FileInfo analyticsDetail, Request request) throws NotFoundException {
        HttpHeaders httpHeaders = request.getHeaders();
        AuthDTO authDTO = null;
        String tenantDomain = null;
        String uploadedFileName = httpHeaders.getHeaderString(UploadServiceConstants.FILE_NAME_HEADER);
        try {
            authDTO = AuthenticatorUtil.authorizeUser(httpHeaders);
            String tenantAwareUsername = null;
            if (authDTO.isAuthenticated()) {
                tenantDomain = authDTO.getTenantDomain();
                if (uploadedFileName == null || uploadedFileName.isEmpty()) {
                    String errorMessage = "FileName Header is missing.\n";
                    log.error(errorMessage);
                    return Response.status(Response.Status.BAD_REQUEST).entity(errorMessage).build();
                }
                if (!uploadedFileName.matches(UploadServiceConstants.FILE_NAME_REGEX)) {
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity("FileName Header is in incorrect format.\n").build();
                }
                //Add the uploaded file into the database
                long timeStamp = Long.parseLong(uploadedFileName.split("\\.")[2]);
                UploadedFileInfoDTO dto = new UploadedFileInfoDTO(tenantDomain, uploadedFileName, timeStamp);
//            FIleEventAdapterDAO.persistUploadedFile(dto, request.);
                log.info("Successfully uploaded the API Usage file [" + uploadedFileName + "] for Tenant : "
                        + tenantDomain + " By : " + tenantAwareUsername);
                return Response.status(Response.Status.CREATED).entity("File uploaded successfully.\n").build();
            } else {
                log.warn("Unauthorized access for API Usage Upload Service. " + authDTO.getMessage());
                return Response.status(authDTO.getResponseStatus()).entity(authDTO.getMessage() +
                        authDTO.getDescription()).build();
            }
        } catch (AuthenticationException e) {
            String msg = "Error occurred while uploading API Usage file : " + uploadedFileName + " for tenant : "
                    + tenantDomain;
            log.error(msg, e);
            return Response.status(authDTO.getResponseStatus()).entity(authDTO.getMessage() +
                    authDTO.getDescription()).build();
        }

    }
}
