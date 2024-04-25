
package com.czertainly.signserver.csc.clients.signserver.ws.dto;

import jakarta.xml.bind.annotation.*;


/**
 * <p>Java class for getPKCS10CertificateRequestForAlias2Response complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="getPKCS10CertificateRequestForAlias2Response"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="return" type="{http://adminws.signserver.org/}certReqData" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "getPKCS10CertificateRequestForAlias2Response", namespace = "http://adminws.signserver.org/", propOrder = {
    "_return"
})
public class GetPKCS10CertificateRequestForAlias2Response {

    @XmlElement(name = "return")
    protected CertReqData _return;

    /**
     * Gets the value of the return property.
     * 
     * @return
     *     possible object is
     *     {@link CertReqData }
     *     
     */
    public CertReqData getReturn() {
        return _return;
    }

    /**
     * Sets the value of the return property.
     * 
     * @param value
     *     allowed object is
     *     {@link CertReqData }
     *     
     */
    public void setReturn(CertReqData value) {
        this._return = value;
    }

}
