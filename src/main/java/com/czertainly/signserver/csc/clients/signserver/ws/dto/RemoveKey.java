
package com.czertainly.signserver.csc.clients.signserver.ws.dto;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for removeKey complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="removeKey"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="signerId" type="{http://www.w3.org/2001/XMLSchema}int"/&gt;
 *         &lt;element name="alias" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlRootElement(namespace = "http://adminws.signserver.org/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "removeKey", propOrder = {
    "signerId",
    "alias"
})
public class RemoveKey {

    protected int signerId;
    protected String alias;

    /**
     * Gets the value of the signerId property.
     * 
     */
    public int getSignerId() {
        return signerId;
    }

    /**
     * Sets the value of the signerId property.
     * 
     */
    public void setSignerId(int value) {
        this.signerId = value;
    }

    /**
     * Gets the value of the alias property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getAlias() {
        return alias;
    }

    /**
     * Sets the value of the alias property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setAlias(String value) {
        this.alias = value;
    }

}
