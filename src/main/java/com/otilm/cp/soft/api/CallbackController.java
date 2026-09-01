package com.otilm.cp.soft.api;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.token.TokenInstanceDto;
import com.otilm.cp.soft.attribute.EcdsaKeyAttributes;
import com.otilm.cp.soft.attribute.FalconKeyAttributes;
import com.otilm.cp.soft.attribute.MLDSAKeyAttributes;
import com.otilm.cp.soft.attribute.MLKEMAttributes;
import com.otilm.cp.soft.attribute.RsaKeyAttributes;
import com.otilm.cp.soft.attribute.SLHDSAKeyAttributes;
import com.otilm.cp.soft.attribute.TokenInstanceAttributes;
import com.otilm.cp.soft.exception.NotSupportedException;
import com.otilm.cp.soft.service.TokenInstanceService;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/cryptographyProvider/callbacks")
public class CallbackController {

    private TokenInstanceService tokenInstanceService;

    @Autowired
    public void setTokenInstanceService(TokenInstanceService tokenInstanceService) {
        this.tokenInstanceService = tokenInstanceService;
    }

    @GetMapping(path = "/keyspec/{algorithm}/attributes", produces = "application/json")
    public List<BaseAttribute> getKeySpecAttributes(@PathVariable KeyAlgorithm algorithm) {

        switch (algorithm) {
            case RSA -> {
                return RsaKeyAttributes.getRsaKeySpecAttributes();
            }
            case ECDSA -> {
                return EcdsaKeyAttributes.getEcdsaKeySpecAttributes();
            }
            case FALCON -> {
                return FalconKeyAttributes.getFalconKeySpecAttributes();
            }
            case MLDSA -> {
                return MLDSAKeyAttributes.getMldsaKeySpecAttributes();
            }
            case SLHDSA -> {
                return SLHDSAKeyAttributes.getSlhDsaKeySpecAttributes();
            }
            case MLKEM -> {
                return MLKEMAttributes.getMLKEMKeySpecAttributes();
            }
            default -> throw new NotSupportedException("Algorithm not supported");
        }

    }

    @GetMapping(path = "/token/{option}/attributes", produces = "application/json")
    public List<BaseAttribute> getCreateTokenAttributes(@PathVariable String option) {

        switch (option) {
            case "new" -> {
                return TokenInstanceAttributes.getNewTokenAttributesWithoutInfo();
            }
            case "existing" -> {
                return TokenInstanceAttributes
                        .getExistingTokenAttributes(
                                tokenInstancesToStringContentList(tokenInstanceService.listTokenInstances()));
            }
            default -> throw new NotSupportedException("Option for token creation not supported");
        }

    }

    private List<BaseAttributeContentV2<?>> tokenInstancesToStringContentList(
            List<TokenInstanceDto> tokenInstanceDtos) {
        return tokenInstanceDtos
                .stream()
                .<BaseAttributeContentV2<?>>map(tokenInstanceDto -> new StringAttributeContentV2(
                        tokenInstanceDto.getName(), tokenInstanceDto.getUuid()))
                .toList();
    }

}
