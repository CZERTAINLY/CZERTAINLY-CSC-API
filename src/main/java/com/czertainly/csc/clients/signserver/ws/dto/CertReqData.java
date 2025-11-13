package com.czertainly.csc.clients.signserver.ws.dto;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for certReqData complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="certReqData"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="armored" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="binary" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/&gt;
 *         &lt;element name="contentType" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="fileSuffix" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 *
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "certReqData", propOrder = {
        "armored",
        "binary",
        "contentType",
        "fileSuffix"
})
public class CertReqData {

    protected String armored;
    protected byte[] binary;
    protected String contentType;
    protected String fileSuffix;

    /**
     * Gets the value of the armored property.
     *
     * @return possible object is
     * {@link String }
     *
     */
    public String getArmored() {
        return armored;
    }

    /**
     * Sets the value of the armored property.
     *
     * @param value allowed object is
     *              {@link String }
     *
     */
    public void setArmored(String value) {
        this.armored = value;
    }

    /**
     * Gets the value of the binary property.
     *
     * @return possible object is
     * byte[]
     */
    public byte[] getBinary() {
        return binary;
    }

    /**
     * Sets the value of the binary property.
     *
     * @param value allowed object is
     *              byte[]
     */
    public void setBinary(byte[] value) {
        this.binary = value;
    }

    /**
     * Gets the value of the contentType property.
     *
     * @return possible object is
     * {@link String }
     *
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * Sets the value of the contentType property.
     *
     * @param value allowed object is
     *              {@link String }
     *
     */
    public void setContentType(String value) {
        this.contentType = value;
    }

    /**
     * Gets the value of the fileSuffix property.
     *
     * @return possible object is
     * {@link String }
     *
     */
    public String getFileSuffix() {
        return fileSuffix;
    }

    /**
     * Sets the value of the fileSuffix property.
     *
     * @param value allowed object is
     *              {@link String }
     *
     */
    public void setFileSuffix(String value) {
        this.fileSuffix = value;
    }

}
