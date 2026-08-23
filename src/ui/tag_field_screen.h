#pragma once

// Which Spoolman extra field the scale writes tag UIDs into. A single choice
// out of the conventions the ecosystem settled on - see services/tag_field.h.
//
// Reached from the extra fields menu, which is where the field the choice
// names is checked and created.
void buildTagFieldScreen();

// Whether the screen was opened during first setup, which decides the header:
// a back button outside setup, the red close button inside it.
void setTagFieldSetupFlow(bool in_setup);
