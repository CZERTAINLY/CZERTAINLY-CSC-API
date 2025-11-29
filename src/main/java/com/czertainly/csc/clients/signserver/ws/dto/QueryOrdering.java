package com.czertainly.csc.clients.signserver.ws.dto;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlSchemaType;
import jakarta.xml.bind.annotation.XmlType;


/**
 * <p>Java class for queryOrdering complex type.
 *
 * <p>The following schema fragment specifies the expected content contained within this class.
 *
 * <pre>
 * &lt;complexType name="queryOrdering"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="column" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="order" type="{http://adminws.signserver.org/}order" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 *
 *
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "queryOrdering", propOrder = {
        "column",
        "order"
})
public class QueryOrdering {

    protected String column;
    @XmlSchemaType(name = "string")
    protected Order order;

    /**
     * Gets the value of the column property.
     *
     * @return possible object is
     * {@link String }
     *
     */
    public String getColumn() {
        return column;
    }

    /**
     * Sets the value of the column property.
     *
     * @param value allowed object is
     *              {@link String }
     *
     */
    public void setColumn(String value) {
        this.column = value;
    }

    /**
     * Gets the value of the order property.
     *
     * @return possible object is
     * {@link Order }
     *
     */
    public Order getOrder() {
        return order;
    }

    /**
     * Sets the value of the order property.
     *
     * @param value allowed object is
     *              {@link Order }
     *
     */
    public void setOrder(Order value) {
        this.order = value;
    }

}
