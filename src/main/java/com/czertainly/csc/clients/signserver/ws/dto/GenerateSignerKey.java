package com.czertainly.csc.clients.signserver.ws.dto;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for generateSignerKey complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="generateSignerKey"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="signerId" type="{http://www.w3.org/2001/XMLSchema}int"/&gt;
 *         &lt;element name="keyAlgorithm" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="keySpec" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="alias" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="authCode" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 */
@XmlRootElement(namespace = "http://adminws.signserver.org/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "generateSignerKey", propOrder = {
        "signerId",
        "keyAlgorithm",
        "keySpec",
        "alias",
        "authCode"
})
public class GenerateSignerKey {

    protected int signerId;
    protected String keyAlgorithm;
    protected String keySpec;
    protected String alias;
    protected String authCode;

    /**
     * Gets the value of the signerId property.
     */
    public int getSignerId() {
        return signerId;
    }

    /**
     * Sets the value of the signerId property.
     */
    public void setSignerId(int value) {
        this.signerId = value;
    }

    /**
     * Gets the value of the keyAlgorithm property.
     *
     * @return possible object is
     * {@link String }
     */
    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    /**
     * Sets the value of the keyAlgorithm property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setKeyAlgorithm(String value) {
        this.keyAlgorithm = value;
    }

    /**
     * Gets the value of the keySpec property.
     *
     * @return possible object is
     * {@link String }
     */
    public String getKeySpec() {
        return keySpec;
    }

    /**
     * Sets the value of the keySpec property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setKeySpec(String value) {
        this.keySpec = value;
    }

    /**
     * Gets the value of the alias property.
     *
     * @return possible object is
     * {@link String }
     */
    public String getAlias() {
        return alias;
    }

    /**
     * Sets the value of the alias property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setAlias(String value) {
        this.alias = value;
    }

    /**
     * Gets the value of the authCode property.
     *
     * @return possible object is
     * {@link String }
     */
    public String getAuthCode() {
        return authCode;
    }

    /**
     * Sets the value of the authCode property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setAuthCode(String value) {
        this.authCode = value;
    }

}
