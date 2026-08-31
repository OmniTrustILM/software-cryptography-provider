package com.czertainly.cp.soft.api;

import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttributeV2;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.connector.cryptography.token.TokenInstanceDto;
import com.czertainly.cp.soft.exception.NotSupportedException;
import com.czertainly.cp.soft.service.TokenInstanceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The two attribute callbacks the platform invokes while an operator fills in a form. Their
 * paths and the shape of what they return are part of the connector's contract, and the
 * key specification callback is keyed on the selected algorithm.
 */
class CallbackControllerTest {

    private TokenInstanceService tokenInstanceService;
    private CallbackController controller;

    @BeforeEach
    void setUp() {
        tokenInstanceService = mock(TokenInstanceService.class);
        controller = new CallbackController();
        controller.setTokenInstanceService(tokenInstanceService);
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({
            "RSA,     data_rsaKeySize",
            "ECDSA,   data_ecdsaCurve",
            "FALCON,  data_falconDegree",
            "MLDSA,   data_mldsaLevel",
            "SLHDSA,  data_slhdsaSecurityCategory",
            "MLKEM,   data_mlkemLevel"
    })
    void eachAlgorithmReturnsItsOwnSpecificationAttributes(KeyAlgorithm algorithm, String firstAttribute) {
        List<BaseAttribute> attributes = controller.getKeySpecAttributes(algorithm);

        assertFalse(attributes.isEmpty(), algorithm + " returned no specification attributes");
        assertEquals(firstAttribute, attributes.get(0).getName());
    }

    @Test
    void anUnsupportedAlgorithmIsRejected() {
        assertThrows(NotSupportedException.class, () -> controller.getKeySpecAttributes(KeyAlgorithm.UNKNOWN));
    }

    @Test
    void theNewTokenOptionAsksForNameAndCodeWithoutTheInformationalAttribute() {
        List<BaseAttribute> attributes = controller.getCreateTokenAttributes("new");

        assertEquals(List.of("data_createTokenAction", "data_newTokenName", "data_tokenCode"),
                attributes.stream().map(BaseAttribute::getName).toList());
    }

    @Test
    void theExistingTokenOptionOffersTheTokensThatExist() {
        TokenInstanceDto first = new TokenInstanceDto();
        first.setName("first");
        first.setUuid(UUID.randomUUID().toString());
        TokenInstanceDto second = new TokenInstanceDto();
        second.setName("second");
        second.setUuid(UUID.randomUUID().toString());
        when(tokenInstanceService.listTokenInstances()).thenReturn(List.of(first, second));

        List<BaseAttribute> attributes = controller.getCreateTokenAttributes("existing");

        assertEquals(List.of("data_createTokenAction", "data_existingToken", "data_tokenCode"),
                attributes.stream().map(BaseAttribute::getName).toList());

        // Each token is offered by name, carrying its UUID as the value that gets stored.
        DataAttributeV2 selection = (DataAttributeV2) attributes.get(1);
        assertEquals(List.of("first", "second"),
                selection.getContent().stream().map(c -> c.getReference()).toList());
        assertEquals(List.of(first.getUuid(), second.getUuid()),
                selection.getContent().stream().map(c -> c.getData()).toList());
    }

    @Test
    void theExistingTokenOptionCopesWithNoTokensAtAll() {
        when(tokenInstanceService.listTokenInstances()).thenReturn(List.of());

        List<BaseAttribute> attributes = controller.getCreateTokenAttributes("existing");

        DataAttributeV2 selection = (DataAttributeV2) attributes.get(1);
        assertTrue(selection.getContent().isEmpty());
    }

    @Test
    void anUnknownTokenOptionIsRejected() {
        assertThrows(NotSupportedException.class, () -> controller.getCreateTokenAttributes("something-else"));
    }
}
