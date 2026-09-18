/*
 * Copyright Verizon Media
 * Licensed under the terms of the Apache 2.0 license. See LICENSE file in project root for terms.
 */
package com.yahoo.smtpnio.async.request;

import java.nio.charset.StandardCharsets;

import javax.annotation.Nonnull;

import com.yahoo.smtpnio.async.exception.SmtpAsyncClientException;
import com.yahoo.smtpnio.async.response.SmtpResponse;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

/**
 * This defines the base class that all SMTP commands inherit from.
 */
public abstract class AbstractSmtpCommand implements SmtpRequest {

    /** Constant for the CR and LF bytes. */
    protected static final byte[] CRLF_B = { '\r', '\n' };

    /** Highest code point considered a C0 control character, ie. the last character before SPACE. */
    private static final char LAST_C0_CONTROL_CHAR = 0x1F;

    /** The DEL control character. */
    private static final char DEL_CHAR = 0x7F;

    /** The SMTP command name. */
    protected String command;

    /**
     * Constructor for a SMTP command with no arguments.
     *
     * @param command the command string, eg. "QUIT"
     */
    protected AbstractSmtpCommand(@Nonnull final String command) {
        this.command = command;
    }

    /**
     * Ensures a caller-supplied command argument cannot alter the structure of the command line it is written into.
     *
     * <p>
     * Arguments are written to the wire verbatim, so a control character in an argument is interpreted by the server as
     * protocol syntax rather than as data. A CR or LF terminates the command line and turns the remainder of the argument into
     * an additional command of the caller's choosing; NUL and SOH are field separators inside the SASL payloads used by the AUTH
     * commands. RFC 5321 permits none of these in an address, domain or parameter, so all C0 controls and DEL are rejected here
     * rather than silently forwarded.
     * </p>
     *
     * @param value the argument to validate
     * @param name the name of the argument, used in the error message
     * @return the argument, unchanged, when it is safe to write to the wire
     * @throws SmtpAsyncClientException when the argument contains a control character
     */
    @Nonnull
    protected static String validateArgument(@Nonnull final String value, @Nonnull final String name) throws SmtpAsyncClientException {
        for (int i = 0; i < value.length(); i++) {
            final char c = value.charAt(i);
            if (c <= LAST_C0_CONTROL_CHAR || c == DEL_CHAR) {
                // the offending value is deliberately excluded from the message, it may hold a credential
                throw new SmtpAsyncClientException(SmtpAsyncClientException.FailureType.INVALID_INPUT,
                        new StringBuilder("The ").append(name).append(" argument contains an illegal control character (0x")
                                .append(Integer.toHexString(c)).append(") at index ").append(i).append('.').toString());
            }
        }
        return value;
    }

    @Override
    public void cleanup() {
        command = null;
    }

    /**
     * @return the type of command
     */
    @Override
    public abstract SmtpCommandType getCommandType();

    @Nonnull
    @Override
    public ByteBuf getCommandLineBytes() throws SmtpAsyncClientException {
        return Unpooled.buffer(command.length() + CRLF_B.length)
                .writeBytes(command.getBytes(StandardCharsets.US_ASCII))
                .writeBytes(CRLF_B);
    }

    @Override
    public boolean isCommandLineDataSensitive() {
        return false;
    }

    @Nonnull
    @Override
    public String getDebugData() {
        return "";
    }

    @Override
    public ByteBuf getNextCommandLineAfterContinuation(@Nonnull final SmtpResponse serverResponse) throws SmtpAsyncClientException {
        throw new SmtpAsyncClientException(SmtpAsyncClientException.FailureType.OPERATION_NOT_SUPPORTED_FOR_COMMAND);
    }
}
