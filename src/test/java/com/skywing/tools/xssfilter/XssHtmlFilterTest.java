package com.skywing.tools.xssfilter;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Created by robin on 2017/7/8.
 */
public class XssHtmlFilterTest {
    protected XssHtmlFilter xssHtmlFilter;
    protected DefaultXssHtmlFilterConfig filterConfig;

    @Before
    public void setUp() {
        filterConfig = new DefaultXssHtmlFilterConfig();
        xssHtmlFilter = new XssHtmlFilter(filterConfig);
    }

    @After
    public void tearDown() {
        xssHtmlFilter = null;
        filterConfig = null;
    }

    @Test
    public void testBasics() {
        assertThat(xssHtmlFilter.filter(""), is(""));
        assertThat(xssHtmlFilter.filter("hello"), is("hello"));
    }

    @Test
    public void testBalancingTags() {
        assertThat(xssHtmlFilter.filter("<b>hello"), is("<b>hello</b>"));
        assertThat(xssHtmlFilter.filter("<b>hello"), is("<b>hello</b>"));
        assertThat(xssHtmlFilter.filter("hello<b>"), is("hello"));
        assertThat(xssHtmlFilter.filter("hello</b>"), is("hello"));
        assertThat(xssHtmlFilter.filter("hello<b/>"), is("hello"));
        assertThat(xssHtmlFilter.filter("<b><b><b>hello"), is("<b><b><b>hello</b></b></b>"));
        assertThat(xssHtmlFilter.filter("</b><b>"), is(""));
        assertThat(xssHtmlFilter.filter("hello<b>HELLO"), is("hello<b>HELLO</b>"));
    }

    @Test
    public void testEndSlashes() {
        assertThat(xssHtmlFilter.filter("<img>"), is("<img />"));
        assertThat(xssHtmlFilter.filter("<img/>"), is("<img />"));
        assertThat(xssHtmlFilter.filter("<b/></b>"), is(""));
    }

    @Test
    public void testBalancingAngleBrackets() {
        if (filterConfig.isAlwaysMakeTag()) {
            assertThat(xssHtmlFilter.filter("<img src=\"foo\""), is("<img src=\"foo\" />"));
            assertThat(xssHtmlFilter.filter("i>"), is(""));
            assertThat(xssHtmlFilter.filter("<img src=\"foo\"/"), is("<img src=\"foo\" />"));
            assertThat(xssHtmlFilter.filter(">"), is(""));
            assertThat(xssHtmlFilter.filter("foo<b"), is("foo"));
            assertThat(xssHtmlFilter.filter("b>foo"), is("<b>foo</b>"));
            assertThat(xssHtmlFilter.filter("><b"), is(""));
            assertThat(xssHtmlFilter.filter("b><"), is(""));
            assertThat(xssHtmlFilter.filter("><b>"), is(""));
        } else {
            assertThat(xssHtmlFilter.filter("<img src=\"foo\""), is("&lt;img src=\"foo\""));
            assertThat(xssHtmlFilter.filter("b>"), is("b&gt;"));
            assertThat(xssHtmlFilter.filter("<img src=\"foo\"/"), is("&lt;img src=\"foo\"/"));
            assertThat(xssHtmlFilter.filter(">"), is("&gt;"));
            assertThat(xssHtmlFilter.filter("foo<b"), is("foo&lt;b"));
            assertThat(xssHtmlFilter.filter("b>foo"), is("b&gt;foo"));
            assertThat(xssHtmlFilter.filter("><b"), is("&gt;&lt;b"));
            assertThat(xssHtmlFilter.filter("b><"), is("b&gt;&lt;"));
            assertThat(xssHtmlFilter.filter("><b>"), is("&gt;"));
        }
    }

    @Test
    public void testAttributes() {
        assertThat(xssHtmlFilter.filter("<img src=foo>"), is("<img src=\"foo\" />"));
        assertThat(xssHtmlFilter.filter("<img asrc=foo>"), is("<img />"));
        assertThat(xssHtmlFilter.filter("<img src=test test>"), is("<img src=\"test\" />"));
    }

    @Test
    public void testDisallowScriptTags() {
        assertThat(xssHtmlFilter.filter("<script>"), is(""));
        String result = filterConfig.isAlwaysMakeTag() ? "" : "&lt;script";
        assertThat(xssHtmlFilter.filter("<script"), is(result));
        assertThat(xssHtmlFilter.filter("<script/>"), is(""));
        assertThat(xssHtmlFilter.filter("</script>"), is(""));
        assertThat(xssHtmlFilter.filter("<script woo=yay>"), is(""));
        assertThat(xssHtmlFilter.filter("<script woo=\"yay\">"), is(""));
        assertThat(xssHtmlFilter.filter("<script woo=\"yay>"), is(""));
        assertThat(xssHtmlFilter.filter("<script woo=\"yay<b>"), is(""));
        assertThat(xssHtmlFilter.filter("<script<script>>"), is(""));
        assertThat(xssHtmlFilter.filter("<<script>script<script>>"), is("script"));
        assertThat(xssHtmlFilter.filter("<<script><script>>"), is(""));
        assertThat(xssHtmlFilter.filter("<<script>script>>"), is(""));
        assertThat(xssHtmlFilter.filter("<<script<script>>"), is(""));
    }

    @Test
    public void testProtocols() {
        assertThat(xssHtmlFilter.filter("<a href=\"http://foo\">bar</a>"), is("<a href=\"http://foo\">bar</a>"));
        assertThat(xssHtmlFilter.filter("<a href=\"https://foo\">bar</a>"), is("<a href=\"https://foo\">bar</a>"));
        // we don't allow ftp. t("<a href=\"ftp://foo\">bar</a>", "<a href=\"ftp://foo\">bar</a>");
        assertThat(xssHtmlFilter.filter("<a href=\"mailto:foo\">bar</a>"), is("<a href=\"mailto:foo\">bar</a>"));
        assertThat(xssHtmlFilter.filter("<a href=\"javascript:foo\">bar</a>"), is("<a href=\"#foo\">bar</a>"));
        assertThat(xssHtmlFilter.filter("<a href=\"java script:foo\">bar</a>"), is("<a href=\"#foo\">bar</a>"));
        assertThat(xssHtmlFilter.filter("<a href=\"java\tscript:foo\">bar</a>"), is("<a href=\"#foo\">bar</a>"));
        assertThat(xssHtmlFilter.filter("<a href=\"java\nscript:foo\">bar</a>"), is("<a href=\"#foo\">bar</a>"));
        assertThat(xssHtmlFilter.filter("<a href=\"java" + XssHtmlFilter.chr(1) + "script:foo\">bar</a>"), is("<a href=\"#foo\">bar</a>"));
        assertThat(xssHtmlFilter.filter("<a href=\"jscript:foo\">bar</a>"), is("<a href=\"#foo\">bar</a>"));
        assertThat(xssHtmlFilter.filter("<a href=\"vbscript:foo\">bar</a>"), is("<a href=\"#foo\">bar</a>"));
        assertThat(xssHtmlFilter.filter("<a href=\"view-source:foo\">bar</a>"), is("<a href=\"#foo\">bar</a>"));
    }

    @Test
    public void testSelfClosingTags() {
        assertThat(xssHtmlFilter.filter("<img src=\"a\">"), is("<img src=\"a\" />"));
        assertThat(xssHtmlFilter.filter("<img src=\"a\">foo</img>"), is("<img src=\"a\" />foo"));
        assertThat(xssHtmlFilter.filter("</img>"), is(""));
    }

    @Test
    public void testComments() {
        if (filterConfig.isStripComment()) {
            assertThat(xssHtmlFilter.filter("<!-- a<b --->"), is(""));
        } else {
            assertThat(xssHtmlFilter.filter("<!-- a<b --->"), is("<!-- a&lt;b --->"));
        }
    }

    @Test
    public void testEntities() {
        assertThat(xssHtmlFilter.filter("&nbsp;"), is("&nbsp;"));
        assertThat(xssHtmlFilter.filter("&amp;"), is("&amp;"));
        assertThat(xssHtmlFilter.filter("test &nbsp; test"), is("test &nbsp; test"));
        assertThat(xssHtmlFilter.filter("test &amp; test"), is("test &amp; test"));
        assertThat(xssHtmlFilter.filter("&nbsp;&nbsp;"), is("&nbsp;&nbsp;"));
        assertThat(xssHtmlFilter.filter("&amp;&amp;"), is("&amp;&amp;"));
        assertThat(xssHtmlFilter.filter("test &nbsp;&nbsp; test"), is("test &nbsp;&nbsp; test"));
        assertThat(xssHtmlFilter.filter("test &amp;&amp; test"), is("test &amp;&amp; test"));
        assertThat(xssHtmlFilter.filter("&amp;&nbsp;"), is("&amp;&nbsp;"));
        assertThat(xssHtmlFilter.filter("test &amp;&nbsp; test"), is("test &amp;&nbsp; test"));
    }

    @Test
    public void testDollar() {
        String text = "modeling & US MSRP $81.99, (Not Included)";
        String result = "modeling &amp; US MSRP $81.99, (Not Included)";

        assertThat(xssHtmlFilter.filter(text), is(result));
    }

    @Test
    public void testBr() {
        assertThat(xssHtmlFilter.filter("test <br> test <br>"), is("test <br /> test <br />"));
    }
}
