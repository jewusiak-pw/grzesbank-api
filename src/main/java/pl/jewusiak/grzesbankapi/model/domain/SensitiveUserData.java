package pl.jewusiak.grzesbankapi.model.domain;

import jakarta.persistence.Embeddable;
import jakarta.persistence.Entity;
import lombok.Data;

@Data
@Embeddable
public class SensitiveUserData {
    private String pesel;
    private String documentNumber;
}
