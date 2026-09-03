package com.otilm.cp.soft.model;

/**
 * What inspecting a token context found, without acting on it.
 *
 * @param availability whether the token can be used
 * @param detail a short explanation for a caller, never quoting the code the context carried
 */
public record TokenState(TokenAvailability availability, String detail) {
}
