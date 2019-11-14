package com.skywing.tools.xssfilter;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/**
 * Created by robin on 2017/7/5.
 */
public class DefaultXssHtmlFilterConfig implements XssHtmlFilterConfig {

    //allowed html elements, along with allowed attributes for each element
    private HashMap<String, List<String>> allowedElements;

    //disallowed html elements
    private List<String> disallowedElements;

    //entities allowed within html markup
    private List<String> allowedEntities;

    //allowed protocols
    private List<String> allowedProtocols;

    //attributes which should be checked for valid protocols
    private List<String> protocolAttributes;

    //tags which should be removed if they contain no content (e.g. "<b></b>" or "<b />")
    private List<String> removeBlanks;

    //html elements which must always be self-closing (e.g. "<img />")
    private List<String> selfClosingTags;

    //html elements which must always have separate opening and closing tags (e.g. "<b></b>")
    private List<String> needClosingTags;

    public DefaultXssHtmlFilterConfig() {
        allowedElements = new HashMap<String, List<String>>();
        allowedElements.put("a", Arrays.asList("target", "href", "title", "style", "class", "id"));
        allowedElements.put("abbr", Arrays.asList("title", "style", "class", "id"));
        allowedElements.put("address", Arrays.asList("style", "class", "id"));
        allowedElements.put("area", Arrays.asList("shape", "coords", "href", "alt", "style", "class", "id"));
        allowedElements.put("article", Arrays.asList("style", "class", "id"));
        allowedElements.put("aside", Arrays.asList("style", "class", "id"));
        allowedElements.put("audio", Arrays.asList("autoplay", "controls", "loop", "preload", "src", "style", "class", "id"));
        allowedElements.put("b", Arrays.asList("style", "class", "id"));
        allowedElements.put("bdi", Arrays.asList("dir"));
        allowedElements.put("bdo", Arrays.asList("dir"));
        allowedElements.put("big", Collections.<String>emptyList());
        allowedElements.put("blockquote", Arrays.asList("cite", "style", "class", "id"));
        allowedElements.put("br", Collections.<String>emptyList());
        allowedElements.put("caption", Arrays.asList("style", "class", "id"));
        allowedElements.put("center", Collections.<String>emptyList());
        allowedElements.put("cite", Collections.<String>emptyList());
        allowedElements.put("code", Arrays.asList("style", "class", "id"));
        allowedElements.put("col", Arrays.asList("align", "valign", "span", "width", "style", "class", "id"));
        allowedElements.put("colgroup", Arrays.asList("align", "valign", "span", "width", "style", "class", "id"));
        allowedElements.put("dd", Arrays.asList("style", "class", "id"));
        allowedElements.put("del", Arrays.asList("datetime", "style", "class", "id"));
        allowedElements.put("details", Arrays.asList("open", "style", "class", "id"));
        allowedElements.put("div", Arrays.asList("style", "class", "id"));
        allowedElements.put("dl", Arrays.asList("style", "class", "id"));
        allowedElements.put("dt", Arrays.asList("style", "class", "id"));
        allowedElements.put("em", Arrays.asList("style", "class", "id"));
        allowedElements.put("embed", Arrays.asList("style", "class", "id", "_url", "type", "pluginspage", "src", "width", "height", "wmode", "play", "loop", "menu", "allowscriptaccess", "allowfullscreen"));
        allowedElements.put("font", Arrays.asList("color", "size", "face", "style", "class", "id"));
        allowedElements.put("footer", Arrays.asList("style", "class", "id"));
        allowedElements.put("h1", Arrays.asList("style", "class", "id"));
        allowedElements.put("h2", Arrays.asList("style", "class", "id"));
        allowedElements.put("h3", Arrays.asList("style", "class", "id"));
        allowedElements.put("h4", Arrays.asList("style", "class", "id"));
        allowedElements.put("h5", Arrays.asList("style", "class", "id"));
        allowedElements.put("h6", Arrays.asList("style", "class", "id"));
        allowedElements.put("header", Arrays.asList("style", "class", "id"));
        allowedElements.put("hr", Arrays.asList("style", "class", "id"));
        allowedElements.put("i", Arrays.asList("style", "class", "id"));
        allowedElements.put("iframe", Arrays.asList("style", "class", "id", "src", "frameborder", "data-latex"));
        allowedElements.put("img", Arrays.asList("src", "alt", "title", "width", "height", "style", "class", "id", "_url"));
        allowedElements.put("ins", Arrays.asList("datetime", "style", "class", "id"));
        allowedElements.put("li", Arrays.asList("style", "class", "id"));
        allowedElements.put("mark", Collections.<String>emptyList());
        allowedElements.put("nav", Collections.<String>emptyList());
        allowedElements.put("ol", Arrays.asList("style", "class", "id"));
        allowedElements.put("p", Arrays.asList("style", "class", "id"));
        allowedElements.put("pre", Arrays.asList("style", "class", "id"));
        allowedElements.put("s", Collections.<String>emptyList());
        allowedElements.put("section", Collections.<String>emptyList());
        allowedElements.put("small", Arrays.asList("style", "class", "id"));
        allowedElements.put("span", Arrays.asList("style", "class", "id"));
        allowedElements.put("sub", Arrays.asList("style", "class", "id"));
        allowedElements.put("sup", Arrays.asList("style", "class", "id"));
        allowedElements.put("strong", Arrays.asList("style", "class", "id"));
        allowedElements.put("table", Arrays.asList("width", "border", "align", "valign", "style", "class", "id"));
        allowedElements.put("tbody", Arrays.asList("align", "valign", "style", "class", "id"));
        allowedElements.put("td", Arrays.asList("width", "rowspan", "colspan", "align", "valign", "style", "class", "id"));
        allowedElements.put("tfoot", Arrays.asList("align", "valign", "style", "class", "id"));
        allowedElements.put("th", Arrays.asList("width", "rowspan", "colspan", "align", "valign", "style", "class", "id"));
        allowedElements.put("thead", Arrays.asList("align", "valign", "style", "class", "id"));
        allowedElements.put("tr", Arrays.asList("rowspan", "align", "valign", "style", "class", "id"));
        allowedElements.put("tt", Arrays.asList("style", "class", "id"));
        allowedElements.put("u", Collections.<String>emptyList());
        allowedElements.put("ul", Arrays.asList("style", "class", "id"));
        allowedElements.put("svg", Arrays.asList("style", "class", "id", "width", "height", "xmlns", "fill", "viewBox"));
        allowedElements.put("video", Arrays.asList("autoplay", "controls", "loop", "preload", "src", "height", "width", "style", "class", "id"));

        disallowedElements = Collections.<String>emptyList();

        allowedEntities = Arrays.asList("amp", "gt", "lt", "quot", "nbsp", "#39");

        allowedProtocols = Arrays.asList("http", "https", "mailto", "ftp");

        protocolAttributes = Arrays.asList("src", "href");

        removeBlanks = Arrays.asList("a", "b", "strong", "i", "em");

        selfClosingTags =  Arrays.asList("img", "area", "br", "col", "embed", "hr");

        needClosingTags =  Arrays.asList("a", "b", "strong", "i", "em");
    }

    public boolean isAllowedElement(String name) {
        return allowedElements.containsKey(name) && !disallowedElements.contains(name);
    }

    public boolean isAllowedAttribute(String name, String attribute) {
        return isAllowedElement(name) && (allowedElements.get(name).contains(attribute));
    }

    public boolean isValidEntity(String entity) {
        return allowedEntities.contains(entity);
    }

    public boolean isAllowedProtocol(String protocol) {
        return allowedProtocols.contains(protocol);
    }

    public boolean isProtocolAttribute(String attribute) {
        return protocolAttributes.contains(attribute);
    }

    public boolean isSelfClosingTag(final String name) {
        return selfClosingTags.contains(name);
    }

    public boolean isNeedClosingTag(final String name) {
        return needClosingTags.contains(name);
    }

    public List<String> getRemoveBlanks() {
        return removeBlanks;
    }

    public boolean isStripComment() {
        return true;
    }

    public boolean isEncodeQuote() {
        return true;
    }

    public boolean isAlwaysMakeTag() {
        return true;
    }
}
