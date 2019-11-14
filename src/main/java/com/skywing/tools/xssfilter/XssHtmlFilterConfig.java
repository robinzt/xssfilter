package com.skywing.tools.xssfilter;

import java.util.List;

/**
 * Created by robin on 2017/7/5.
 */
public interface XssHtmlFilterConfig {

    public boolean isAllowedElement(final String name);

    public boolean isAllowedAttribute(final String name, final String attribute);

    public boolean isValidEntity(final String entity);

    public boolean isAllowedProtocol(final String protocol);

    public boolean isProtocolAttribute(final String attribute);

    public boolean isSelfClosingTag(final String name);

    public boolean isNeedClosingTag(final String name);

    public List<String> getRemoveBlanks();

    public boolean isStripComment();

    public boolean isEncodeQuote();

    public boolean isAlwaysMakeTag();
}
