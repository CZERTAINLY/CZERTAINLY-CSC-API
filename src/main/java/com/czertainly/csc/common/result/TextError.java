package com.czertainly.csc.common.result;

import com.czertainly.csc.common.utils.ThrowableUtil;

public class TextError extends ExtendableErrorValue<String> {

    public TextError(String error) {
        super(error);
    }

    public static TextError of(String error) {
        return new TextError(error);
    }

    public static TextError of(Exception e) {
        return new TextError(ThrowableUtil.chainedString(e));
    }

    private TextError(String error, TextError originalError) {
        super(error, originalError);
    }

    public static TextError of(String template, Object... args) {
        return new TextError(String.format(template, args));
    }

    public TextError extend(String error) {
        return new TextError(error, this);
    }

    public TextError extend(String template, Object... args) {
        return new TextError(String.format(template, args), this);
    }
}
