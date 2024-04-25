
package com.czertainly.signserver.csc.clients.signserver.ws.dto;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlType;

import java.util.ArrayList;
import java.util.List;


/**
 * <p>Java class for queryTokenEntries complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="queryTokenEntries"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="workerId" type="{http://www.w3.org/2001/XMLSchema}int"/&gt;
 *         &lt;element name="startIndex" type="{http://www.w3.org/2001/XMLSchema}int"/&gt;
 *         &lt;element name="max" type="{http://www.w3.org/2001/XMLSchema}int"/&gt;
 *         &lt;element name="condition" type="{http://adminws.signserver.org/}queryCondition" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="ordering" type="{http://adminws.signserver.org/}queryOrdering" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="includeData" type="{http://www.w3.org/2001/XMLSchema}boolean"/&gt;
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
@XmlType(name = "queryTokenEntries", propOrder = {
    "workerId",
    "startIndex",
    "max",
    "condition",
    "ordering",
    "includeData"
})
public class QueryTokenEntries {

    protected int workerId;
    protected int startIndex;
    protected int max;
    protected List<QueryCondition> condition;
    protected List<QueryOrdering> ordering;
    protected boolean includeData;

    /**
     * Gets the value of the workerId property.
     * 
     */
    public int getWorkerId() {
        return workerId;
    }

    /**
     * Sets the value of the workerId property.
     * 
     */
    public void setWorkerId(int value) {
        this.workerId = value;
    }

    /**
     * Gets the value of the startIndex property.
     * 
     */
    public int getStartIndex() {
        return startIndex;
    }

    /**
     * Sets the value of the startIndex property.
     * 
     */
    public void setStartIndex(int value) {
        this.startIndex = value;
    }

    /**
     * Gets the value of the max property.
     * 
     */
    public int getMax() {
        return max;
    }

    /**
     * Sets the value of the max property.
     * 
     */
    public void setMax(int value) {
        this.max = value;
    }

    public void addCondition(QueryCondition condition) {
        if (this.condition == null) {
            this.condition = new ArrayList<>();
        }
        this.condition.add(condition);
    }

    /**
     * Gets the value of the condition property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the Jakarta XML Binding object.
     * This is why there is not a <CODE>set</CODE> method for the condition property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getCondition().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link QueryCondition }
     * 
     * 
     */
    public List<QueryCondition> getCondition() {
        if (this.condition == null) {
            this.condition = new ArrayList<>();
        }
        return this.condition;
    }

    /**
     * Gets the value of the ordering property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the Jakarta XML Binding object.
     * This is why there is not a <CODE>set</CODE> method for the ordering property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getOrdering().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link QueryOrdering }
     * 
     * 
     */
    public List<QueryOrdering> getOrdering() {
        return this.ordering;
    }

    /**
     * Gets the value of the includeData property.
     * 
     */
    public boolean isIncludeData() {
        return includeData;
    }

    /**
     * Sets the value of the includeData property.
     * 
     */
    public void setIncludeData(boolean value) {
        this.includeData = value;
    }

}
