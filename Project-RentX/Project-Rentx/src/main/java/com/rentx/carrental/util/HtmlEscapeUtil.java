package com.rentx.carrental.util;

import org.springframework.web.util.HtmlUtils;

public class HtmlEscapeUtil {
    
    public static String escapeHtml(String input) {
        if (input == null) return null;
        return HtmlUtils.htmlEscape(input.trim());
    }
    
    public static String escapeHtmlAndLimit(String input, int maxLength) {
        if (input == null) return null;
        String trimmed = input.trim();
        if (trimmed.length() > maxLength) {
            trimmed = trimmed.substring(0, maxLength);
        }
        return HtmlUtils.htmlEscape(trimmed);
    }
}